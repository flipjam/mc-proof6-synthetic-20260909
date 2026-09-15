"""Narrow GitHub adapter. All URLs and write bodies originate in trusted code.

Adapted from historical fixed-target writer/object verification and non-force
journal concepts. No historical campaign, Q0, diagnostics or custody imports.
"""
import base64
import http.client
import os
from urllib.parse import quote
from core import *

BASE = '/repos/' + REPOSITORY


class GitHub:
    def __init__(self, config):
        self.c = validate_config(config)
        # Only the isolated privileged job supplies these environment values.
        self.__token = os.environ.pop('BMIN_APP_TOKEN')
        require(bool(self.__token))
        require(os.environ.get('BMIN_INSTALLATION_ID') == str(config['installation_id'])
                and os.environ.get('BMIN_APP_SLUG') == config['app_slug'])
        self.__spent = False

    def _connection(self):
        # Explicit origin, no proxy, redirects, redirects-with-credentials, retry
        # client, shell, Git credential helper or ambient gh authentication.
        return http.client.HTTPSConnection('api.github.com', timeout=30)

    def _headers(self):
        return {'Authorization': 'Bearer ' + self.__token,
                'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                'User-Agent': 'mc-bmin-broker-v1', 'X-GitHub-Api-Version': '2022-11-28',
                'Connection': 'close'}

    def _request(self, method, path, body=None):
        require(method in ('GET', 'POST', 'PATCH') and path.startswith('/'))
        conn = self._connection()
        try:
            conn.request(method, path, body=None if body is None else canonical(body), headers=self._headers())
            response = conn.getresponse()
            raw = response.read(2_000_001)
            require(200 <= response.status < 300 and len(raw) <= 2_000_000)
            return parse(raw)
        finally:
            conn.close()

    def ref(self, ref):
        require(ref in (AUTHORITY, JOURNAL, RUNTIME))
        value = self._request('GET', BASE + '/git/ref/' + ref.removeprefix('refs/'))
        require(value['ref'] == ref and value['object']['type'] == 'commit')
        return sha(value['object']['sha'])

    def read_file(self, commit_sha, filename):
        require(filename in ('history.json', 'journal.json'))
        commit = self._request('GET', BASE + '/git/commits/' + sha(commit_sha))
        require(commit['sha'] == commit_sha)
        tree_sha = sha(commit['tree']['sha'])
        tree = self._request('GET', BASE + '/git/trees/' + tree_sha)
        require(tree['sha'] == tree_sha and tree['truncated'] is False and len(tree['tree']) == 1)
        entry = tree['tree'][0]
        require(entry['path'] == filename and entry['mode'] == '100644' and entry['type'] == 'blob')
        blob_sha = sha(entry['sha'])
        expected_tree = b'100644 ' + filename.encode() + b'\0' + bytes.fromhex(blob_sha)
        require(git_sha('tree', expected_tree) == tree_sha)
        blob = self._request('GET', BASE + '/git/blobs/' + blob_sha)
        require(blob['sha'] == blob_sha and blob['encoding'] == 'base64')
        raw = base64.b64decode(blob['content'].replace('\n', ''), validate=True)
        require(len(raw) <= 2_000_000 and git_sha('blob', raw) == blob_sha)
        value = parse(raw)
        require(raw == canonical(value))
        return [sha(parent['sha']) for parent in commit['parents']], value

    def create(self, plan):
        # Reconstruct, rather than trust any caller-supplied hash/body mapping.
        require(plan == object_plan(plan['filename'], plan['value'], plan['parent'],
                                    plan['message'].removesuffix('\n')))
        blob = self._request('POST', BASE + '/git/blobs',
                             {'content': base64.b64encode(canonical(plan['value'])).decode(), 'encoding': 'base64'})
        require(blob['sha'] == plan['blob_sha'])
        tree = self._request('POST', BASE + '/git/trees', {'tree': [
            {'path': plan['filename'], 'mode': '100644', 'type': 'blob', 'sha': plan['blob_sha']}]})
        require(tree['sha'] == plan['tree_sha'])
        identity = {'name': 'BMIN Broker', 'email': 'bmin@example.invalid', 'date': '2000-01-01T00:00:00Z'}
        commit = self._request('POST', BASE + '/git/commits', dict(message=plan['message'],
            tree=plan['tree_sha'], parents=[plan['parent']], author=identity, committer=identity))
        require(commit['sha'] == plan['sha'])
        require(self.read_file(plan['sha'], plan['filename']) == ([plan['parent']], plan['value']))

    def append_journal(self, plan):
        require(plan['filename'] == 'journal.json' and self.ref(JOURNAL) == plan['parent'])
        value = self._request('PATCH', BASE + '/git/refs/' + JOURNAL.removeprefix('refs/'),
                              {'sha': plan['sha'], 'force': False})
        require(value['ref'] == JOURNAL and value['object']['sha'] == plan['sha'])

    def policy(self):
        """Resolve the fixed current applicable provider rules; no proposal policy."""
        rules = []
        for ident in self.c['ruleset_ids']:
            item = self._request('GET', BASE + '/rulesets/' + str(ident))
            require(type(item['id']) is int and item['id'] == ident)
            # Reuse accepted stable provider view; include bypass when visible.
            rules.append(dict(view=rule_view.visible(item), bypass_actors=item.get('bypass_actors')))
        effective = {}
        for ref in (AUTHORITY, JOURNAL, RUNTIME):
            items = self._request('GET', BASE + '/rules/branches/' + quote(ref.removeprefix('refs/heads/'), safe='') + '?per_page=100')
            require(type(items) is list and 0 < len(items) < 100)
            effective[ref] = sorted(items, key=canonical)
        # Frozen digest includes the effective list, hence extra applicable
        # inherited or repository rules fail revalidation too.
        return dict(rulesets=rules, effective=effective)

    def check(self, config):
        require(config == self.c)
        validate_config(config)
        repo = self._request('GET', BASE)
        require(type(repo['id']) is int and repo['id'] == REPOSITORY_ID and repo['full_name'] == REPOSITORY)
        scope = self._request('GET', '/installation/repositories?per_page=100')
        require(scope['total_count'] == 1 and len(scope['repositories']) == 1
                and scope['repositories'][0]['id'] == REPOSITORY_ID
                and scope['repositories'][0]['full_name'] == REPOSITORY)
        require(self.ref(RUNTIME) == config['runtime_sha'])
        require(digest(self.policy()) == config['policy_sha256'])

    def send_authority(self, plan, authorization, journal_head):
        from journal import Journal
        require(not self.__spent)
        self.__spent = True  # Consume before every remaining failure boundary.
        journal = Journal(self, self.c)
        require(journal.head == journal_head and journal.stage == 'SEND_ARMED'
                and journal.auth == authorization)
        _, history = self.read_file(authorization['expected_old_sha'], 'history.json')
        exact, constructed = authorize(self.c, journal.intent, authorization['expected_old_sha'], history)
        require(exact == authorization and constructed == plan)
        self.check(self.c)
        require(self.ref(JOURNAL) == journal_head and self.ref(AUTHORITY) == plan['parent'])
        conn = self._connection()
        try:
            # Fixed proof-only ambiguity hook. No response read, no retry and
            # no user fault flag. This is the sole authority transport boundary.
            conn.request('PATCH', BASE + '/git/refs/heads/bmin-v1-authority',
                         body=canonical({'sha': plan['sha'], 'force': False}), headers=self._headers())
            return {'result': 'INDETERMINATE'}
        finally:
            conn.close()
