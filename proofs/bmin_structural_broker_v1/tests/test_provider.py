import ast
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from fixtures import *
from provider import GitHub, BASE
import provider
import launcher


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.guard = patch.object(socket, 'socket', side_effect=AssertionError('OFFLINE_ONLY'))
        self.guard.start()
        self.addCleanup(self.guard.stop)
        self.c = config()
        self.env = dict(BMIN_APP_TOKEN='OFFLINE_INERT', BMIN_INSTALLATION_ID='456', BMIN_APP_SLUG='offline-bmin')

    def adapter(self):
        with patch.dict(os.environ, self.env):
            return GitHub(self.c)

    def armed(self):
        f = Fake(self.c)
        a, plan = authorize(self.c, intent(), self.c['initial_authority_sha'], history())
        f.create(plan)
        j = Journal(f, self.c)
        j.prepare(intent(), a)
        j.arm()
        g = self.adapter()
        g.ref, g.read_file, g.check = f.ref, f.read_file, f.check
        return f, g, a, plan, j

    def test_real_transport_one_patch_false_and_no_response_read(self):
        f, g, a, plan, j = self.armed()
        calls = []
        class Connection:
            def request(self, *args, **kwargs): calls.append((args, kwargs))
            def getresponse(self): raise AssertionError('response must be discarded')
            def close(self): pass
        g._connection = Connection
        self.assertEqual(g.send_authority(plan, a, j.head), {'result': 'INDETERMINATE'})
        with self.assertRaises(ValueError): g.send_authority(plan, a, j.head)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], ('PATCH', BASE+'/git/refs/heads/bmin-v1-authority'))
        self.assertEqual(parse(calls[0][1]['body']), {'sha': plan['sha'], 'force': False})

    def test_real_transport_socket_error_consumes_latch(self):
        f, g, a, plan, j = self.armed()
        calls = []
        class Connection:
            def request(self, *args, **kwargs):
                calls.append(1)
                raise ConnectionError()
            def close(self): pass
        g._connection = Connection
        with self.assertRaises(ConnectionError): g.send_authority(plan, a, j.head)
        with self.assertRaises(ValueError): g.send_authority(plan, a, j.head)
        self.assertEqual(len(calls), 1)

    def test_real_transport_rejects_substituted_authorization(self):
        f, g, a, plan, j = self.armed()
        a = dict(a, candidate_sha='f'*40)
        with self.assertRaises(ValueError): g.send_authority(plan, a, j.head)

    def test_real_transport_revalidates_authority(self):
        f, g, a, plan, j = self.armed()
        f.refs[AUTHORITY] = 'f'*40
        with self.assertRaises(ValueError): g.send_authority(plan, a, j.head)

    def test_wrong_installation(self):
        self.env['BMIN_INSTALLATION_ID'] = '457'
        with self.assertRaises(ValueError): self.adapter()

    def test_wrong_writer_slug(self):
        self.env['BMIN_APP_SLUG'] = 'other-writer'
        with self.assertRaises(ValueError): self.adapter()

    def test_private_token_removed_from_environment(self):
        with patch.dict(os.environ, self.env):
            GitHub(self.c)
            self.assertNotIn('BMIN_APP_TOKEN', os.environ)

    def test_provider_read_identity_mismatch(self):
        g = self.adapter()
        g._request = lambda *a: dict(id=999, full_name=REPOSITORY)
        with self.assertRaises(ValueError): g.check(self.c)

    def test_provider_policy_drift(self):
        g = self.adapter()
        def read(method, path):
            if path == BASE: return dict(id=REPOSITORY_ID, full_name=REPOSITORY)
            return dict(total_count=1, repositories=[dict(id=REPOSITORY_ID, full_name=REPOSITORY)])
        g._request = read
        g.ref = lambda _: self.c['runtime_sha']
        g.policy = lambda: {'changed': True}
        with self.assertRaises(ValueError): g.check(self.c)

    def test_provider_policy_resolution_binds_all_fixed_scopes(self):
        g = self.adapter()
        seen = []
        def read(method, path):
            seen.append(path)
            if '/rulesets/' in path:
                return dict(id=int(path.rsplit('/', 1)[1]), name='offline', target='branch',
                    source_type='Repository', source=REPOSITORY, enforcement='active',
                    conditions={}, rules=[], updated_at='2000-01-01T00:00:00Z', bypass_actors=[])
            return [{'type': 'update', 'ruleset_id': 1}]
        g._request = read
        result = g.policy()
        self.assertEqual(len(seen), 9)
        self.assertEqual(set(result['effective']), {AUTHORITY, JOURNAL, RUNTIME})

    def test_real_object_create_and_read_wire(self):
        import base64
        g = self.adapter()
        a, plan = authorize(self.c, intent(), self.c['initial_authority_sha'], history())
        calls = []
        def api(method, path, body=None):
            calls.append((method, path, body))
            if path.endswith('/git/blobs'):
                self.assertEqual(base64.b64decode(body['content']), canonical(plan['value']))
                return {'sha': plan['blob_sha']}
            if path.endswith('/git/trees'):
                self.assertEqual(body['tree'], [dict(path='history.json', mode='100644', type='blob', sha=plan['blob_sha'])])
                return {'sha': plan['tree_sha']}
            if path.endswith('/git/commits'):
                self.assertEqual(body['parents'], [plan['parent']])
                self.assertEqual(body['author'], body['committer'])
                return {'sha': plan['sha']}
            if '/git/commits/' in path:
                return dict(sha=plan['sha'], tree={'sha': plan['tree_sha']}, parents=[{'sha': plan['parent']}])
            if '/git/trees/' in path:
                return dict(sha=plan['tree_sha'], truncated=False, tree=[
                    dict(path='history.json', mode='100644', type='blob', sha=plan['blob_sha'])])
            return dict(sha=plan['blob_sha'], encoding='base64', content=base64.b64encode(canonical(plan['value'])).decode())
        g._request = api
        g.create(plan)
        self.assertEqual([v[0] for v in calls], ['POST', 'POST', 'POST', 'GET', 'GET', 'GET'])

    def test_unexpected_created_object_sha_blocks(self):
        g = self.adapter()
        _, plan = authorize(self.c, intent(), self.c['initial_authority_sha'], history())
        calls = []
        def api(*args):
            calls.append(args)
            return {'sha': 'f'*40}
        g._request = api
        with self.assertRaises(ValueError): g.create(plan)
        self.assertEqual(len(calls), 1)

    def test_http_redirect_is_not_followed_or_retried(self):
        g = self.adapter()
        calls = []
        class Response:
            status = 302
            def read(self, limit): return b'{}'
        class Connection:
            def request(self, *a, **k): calls.append(a)
            def getresponse(self): return Response()
            def close(self): pass
        g._connection = Connection
        with self.assertRaises(ValueError): g._request('GET', BASE)
        self.assertEqual(len(calls), 1)

    def test_reused_rule_view_normalizes_equivalent_timestamps(self):
        common = dict(id=1, name='offline', target='branch', source_type='Repository',
                      source=REPOSITORY, enforcement='active', conditions={}, rules=[])
        left = rule_view.visible(dict(common, updated_at='2000-01-01T00:00:00Z'))
        right = rule_view.visible(dict(common, updated_at='1999-12-31T16:00:00-08:00'))
        self.assertEqual(left, right)

    def test_full_policy_page_blocks_instead_of_truncating(self):
        g = self.adapter()
        def read(method, path):
            if '/rulesets/' in path:
                return dict(id=int(path.rsplit('/', 1)[1]), name='offline', target='branch',
                    source_type='Repository', source=REPOSITORY, enforcement='active',
                    conditions={}, rules=[], updated_at='2000-01-01T00:00:00Z')
            return [{}]*100
        g._request = read
        with self.assertRaises(ValueError): g.policy()

    def test_candidate_construction_matches_native_git(self):
        a, plan = authorize(self.c, intent(), self.c['initial_authority_sha'], history())
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_ALLOW_PROTOCOL='file', GIT_TERMINAL_PROMPT='0')
            subprocess.run(['git', 'init', '--bare', tmp], env=env, check=True, capture_output=True)
            def git(*args, data=None):
                return subprocess.run(['git', '-C', tmp, *args], input=data,
                    env=env, check=True, capture_output=True, timeout=20).stdout.strip().decode()
            blob = git('hash-object', '-w', '--stdin', data=canonical(plan['value']))
            self.assertEqual(blob, plan['blob_sha'])
            tree = git('mktree', data=f'100644 blob {blob}\thistory.json\n'.encode())
            self.assertEqual(tree, plan['tree_sha'])
            raw = (f'tree {tree}\nparent {plan["parent"]}\n'
                   'author BMIN Broker <bmin@example.invalid> 946684800 +0000\n'
                   'committer BMIN Broker <bmin@example.invalid> 946684800 +0000\n\n' + plan['message']).encode()
            self.assertEqual(git('hash-object', '-t', 'commit', '--stdin', data=raw), plan['sha'])

    def test_workflow_dispatch_only_and_no_raw_input_shell(self):
        raw = (ROOT / WORKFLOW).read_text()
        self.assertEqual(raw.count('${{ inputs.'), 1)
        self.assertIn('BMIN_PROPOSAL: ${{ inputs.proposal }}', raw)
        self.assertNotRegex(raw, r'(?m)^\s+contents: write$')
        self.assertIn('permission-contents: write', raw)
        self.assertNotIn('pull_request', raw)
        self.assertNotIn('push:', raw)
        self.assertIn('cancel-in-progress: false', raw)
        self.assertEqual(raw.count('secrets.'), 1)
        self.assertNotIn('BEGIN PRIVATE KEY', raw)

    def test_preflight_rejects_wrong_job_and_run_attempt(self):
        raw = canonical(self.c)
        env = dict(BMIN_FROZEN_CONFIG=raw.decode(), BMIN_CONFIG_SHA256=hashlib.sha256(raw).hexdigest())
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError): launcher.frozen_config()

    def test_no_public_authorization_or_send_parameter(self):
        import inspect
        self.assertEqual(list(inspect.signature(Broker.submit).parameters), ['self', 'raw'])
        self.assertEqual(list(inspect.signature(Broker.reconcile).parameters), ['self'])
        self.assertNotIn('send_authority', inspect.getsource(Broker.reconcile))


if __name__ == '__main__': unittest.main(verbosity=2)
