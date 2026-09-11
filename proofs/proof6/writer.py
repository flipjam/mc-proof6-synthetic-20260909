"""Proof-6 writer using an official GitHub App installation token."""
import base64
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import re
import urllib.request
import urllib.error
import diagnostics as dia
from ruleset_view import visible

ROOT = Path(__file__).resolve().parents[2]
REPO = 'flipjam/mc-proof6-synthetic-20260909'
REPO_ID = 1363510385
REF = 'refs/heads/proof6-authority'
BASELINE = 'a5a1ccee2e564092d6c9992f83ed2ba11b213475'
APP_ID = 4893415
INSTALLATION = 160504789
PERMISSIONS = {'contents': 'write', 'metadata': 'read'}
CONFIG_DIGEST = 'b5d40e5549e94a1240a179b3e8b4fd883304d1192273ae28e3dbc84292ee7aa2'
VISIBLE_CONFIG_DIGEST = 'ba09309c64e7f683ca00b9f1f394495e9b1b56b07ee850e538096518dd3ccd86'
ACTION_REPOSITORY = 'actions/create-github-app-token'
ACTION_COMMIT = 'bcd2ba49218906704ab6c1aa796996da409d3eb1'
CODE = {
    'proofs/proof1/replay.py': 'ac9c761cf57d74ef68f35213de333c2d071c1f030ad592cae444c3bee576474e',
    'proofs/proof2/gate.py': 'e432172177d7d58d1b9424c4547f31e7223295eeb80d0a3235bd2e7092ca60bf',
}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True).encode('ascii')


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _require(condition):
    if not condition:
        raise ValueError('WRITER_PRECONDITION_FAILED')


def _sha(value):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{40}', value))
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('REDIRECT_REFUSED')


class _Writer:
    def __init__(self, *, frozen_manifest, installation_token,
                 action_installation_id, action_app_slug, runtime_guard, receipt_binding=None):
        self._last_evidence = None
        self._transport_candidate = None
        self._receipt_binding = receipt_binding or {}
        _require(type(installation_token) is str and bool(installation_token))
        _require(action_installation_id == str(INSTALLATION)
                 and action_app_slug == 'mc-proof-6-gate-writer')
        self._installation_token = installation_token
        self._action_installation_id = int(action_installation_id)
        self._action_app_slug = action_app_slug
        self._runtime_guard = runtime_guard
        self._manifest = frozen_manifest
        m = frozen_manifest
        self._writer_digest = _digest(Path(__file__).read_bytes())
        # None is setup-authentication mode only. It cannot mutate authority.
        if m is not None:
            self._check_manifest(m)
        self._manifest_digest = None if m is None else _digest(_canonical(m))
        for name, digest in CODE.items():
            _require(_digest((ROOT / name).read_bytes()) == digest)
        spec = importlib.util.spec_from_file_location('accepted_gate', ROOT / 'proofs/proof2/gate.py')
        self._gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self._gate)
        self._http = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())

    def _check_manifest(self, m):
        _require(m['contract_commit'] == 'c448ec30125943d9197139e028e9d992b25e8176'
                 and m['runtime_variant'] == 'r3d'
                 and m['revision'] == 3 and m['frozen'] is True
                 and m['repository_id'] == REPO_ID and m['repository'] == REPO
                 and m['ref'] == REF and m['baseline_commit'] == BASELINE
                 and m['app_id'] == APP_ID and m['installation_id'] == INSTALLATION
                 and m['app_slug'] == 'mc-proof-6-gate-writer'
                 and m['token_permissions'] == PERMISSIONS
                 and m['action'] == {'repository': ACTION_REPOSITORY,
                                     'commit': ACTION_COMMIT}
                 and m['configuration_sha256'] == CONFIG_DIGEST
                 and m['authority_visible_sha256'] == VISIBLE_CONFIG_DIGEST
                 and m['accepted_code_sha256'] == CODE)
        _require(m['writer_sha256'] == self._writer_digest)
        _require(m['build_sha256'] == _digest((ROOT / 'proofs/proof6/build.json').read_bytes()))
        from proof_control import plan
        _require(m['proof_plan_sha256'] == plan()[1])

    def _call(self, token, method, path, body=None):
        _require(path.startswith('/') and not path.startswith('//'))
        request = urllib.request.Request(
            'https://api.github.com' + path,
            data=None if body is None else _canonical(body), method=method,
            headers={'Authorization': 'Bearer ' + token,
                     'Accept': 'application/vnd.github+json',
                     'Content-Type': 'application/json',
                     'User-Agent': 'mc-proof6-gate-writer',
                     'X-GitHub-Api-Version': '2022-11-28'})
        with self._http.open(request, timeout=30) as response:
            raw = response.read(2_000_001)
        _require(len(raw) <= 2_000_000)
        return json.loads(raw)

    def _installation_access(self):
        """Verify the official action token's exact installation scope."""
        token = self._installation_token
        dia.start('DIA04')
        listing = self._call(token, 'GET', '/installation/repositories?per_page=100')
        dia.ok('DIA04_INSTALLATION_REPOSITORIES_READ_OK')
        dia.start('DIA05')
        _require(listing['total_count'] == 1 and len(listing['repositories']) == 1)
        repo = listing['repositories'][0]
        _require(repo['id'] == REPO_ID and repo['full_name'] == REPO
                 and repo['private'] is False)
        dia.ok('DIA05_REPOSITORY_SELECTION_OK')
        dia.start('DIA06')
        # The action's successful creation and explicit workflow inputs are the
        # configured token boundary. The installation listing is scope evidence;
        # its repository object is not a permission-introspection surface.
        dia.ok('DIA06_TOKEN_BOUNDARY_CONFIGURED')
        return token

    def _revoke_current_token(self, token, evidence):
        # Only this invocation's token; no App key, replacement grant or caller URL.
        request = urllib.request.Request('https://api.github.com/installation/token',
            method='DELETE', headers={'Authorization': 'Bearer ' + token,
                                     'Accept': 'application/vnd.github+json',
                                     'User-Agent': 'mc-proof6-gate-writer',
                                     'X-GitHub-Api-Version': '2022-11-28'})
        with self._http.open(request, timeout=30) as response:
            _require(response.status == 204)
            evidence['token_revocation_status'] = response.status
            evidence['token_revocation_confirmed'] = True

    def _patch(self, token, new, drop_response, evidence):
        permit, self._transport_candidate = self._transport_candidate, None
        _require(permit is not None and permit == _sha(new))
        # NONE and D07 share the exact HTTPS construction/send path. No proxy,
        # redirects, alternate endpoints, automatic retries or response relabeling.
        path = '/repos/' + REPO + '/git/refs/heads/proof6-authority'
        conn = http.client.HTTPSConnection('api.github.com', timeout=30)
        try:
            conn.request('PATCH', path, body=_canonical({'sha': new, 'force': False}),
                         headers={'Authorization': 'Bearer ' + token,
                                  'Accept': 'application/vnd.github+json',
                                  'Content-Type': 'application/json',
                                  'User-Agent': 'mc-proof6-gate-writer',
                                  'X-GitHub-Api-Version': '2022-11-28'})
            evidence['request_transmission_completed'] = True
            if drop_response:
                # No getresponse/read/status access has occurred. Delivery to
                # GitHub remains possible, so this is unknown, never no-update.
                evidence['response_consumed'] = False
                evidence['response_path_discarded'] = True
                raise ConnectionError('PROOF_RESPONSE_DROPPED')
            response = conn.getresponse()
            evidence['response_consumed'] = True
            evidence['http_status'] = response.status
            request_id = response.getheader('x-github-request-id', '')
            if re.fullmatch('[A-Za-z0-9:-]{1,128}', request_id):
                evidence['github_request_id'] = request_id
            if response.status >= 400:
                if (response.status == 401 and evidence.get('proof_operation') == 'D03_REVOKE_CURRENT_TOKEN'
                        and evidence.get('github_request_id')):
                    from d03_rejection import emit
                    emit(self._journal, evidence['pending_record'], evidence)
                raise urllib.error.HTTPError('https://api.github.com' + path,
                                             response.status, 'PATCH_REJECTED', {}, None)
            raw = response.read(2_000_001)
            _require(200 <= response.status < 300 and len(raw) <= 2_000_000)
            return json.loads(raw)
        finally:
            conn.close()

    def _enforcement(self, token):
        bindings = json.loads((ROOT / 'proofs/proof6/diagnostic-bindings.json').read_bytes())
        expected = bindings['authority_views']
        configurations = []
        for ident in (22725068, 22725076):
            stage = 'DIA10' if ident == 22725068 else 'DIA11'
            dia.start(stage)
            item = self._call(token, 'GET', '/repos/' + REPO + '/rulesets/' + str(ident))
            dia.ok(stage + '_AUTHORITY_RULESET_' + str(ident) + '_READ_OK')
            configurations.append(visible(item))
        dia.start('DIA12')
        _require(configurations == expected
                 and _digest(_canonical(configurations)) == VISIBLE_CONFIG_DIGEST)
        dia.ok('DIA12_AUTHORITY_ENFORCEMENT_VIEW_OK')

    def verify_setup_auth(self):
        token = self._installation_access()
        self._enforcement(token)
        runtime = self._runtime_guard(self._manifest)
        dia.ok('DIA13_SETUP_AUTH_VERIFIED')
        return {'result': 'APP_AUTH_SETUP_VERIFIED', 'app_id': APP_ID,
                'app_slug': self._action_app_slug,
                'installation_id': self._action_installation_id,
                'repository_id': REPO_ID, 'permissions': PERMISSIONS,
                'action': {'repository': ACTION_REPOSITORY, 'commit': ACTION_COMMIT},
                'runtime': runtime,
                'mutation_attempted': False}

    def commit_transition(self, proposal_bytes, proof_operation=''):
        evidence = {'result': 'ERROR', 'manifest_sha256': self._manifest_digest,
                    'writer_sha256': self._writer_digest,
                    'accepted_code_sha256': CODE, 'configuration_sha256': CONFIG_DIGEST,
                    'authority_visible_sha256': VISIBLE_CONFIG_DIGEST,
                    'app_id': APP_ID, 'app_slug': 'mc-proof-6-gate-writer',
                    'installation_id': INSTALLATION,
                    'token_permissions': PERMISSIONS,
                    'action': {'repository': ACTION_REPOSITORY, 'commit': ACTION_COMMIT},
                    'old_sha': None, 'new_sha': None, 'candidate_commit': None,
                    'update_attempted': False, 'remote_outcome': 'not_attempted'}
        evidence.update(self._receipt_binding)
        # Keep the same live evidence object across all exception boundaries.
        # After send becomes possible no outer handler may emit a false no-update receipt.
        self._last_evidence = evidence
        try:
            _require(self._manifest is not None)
            from proof_control import FAULTS, plan
            if proof_operation:
                fixed, digest = plan()
                _require(proof_operation in FAULTS
                         and self._receipt_binding.get('proof_operation') == proof_operation
                         and self._receipt_binding.get('proof_plan_sha256') == digest
                         and proposal_bytes == _canonical(fixed['faults'][proof_operation]['proposal']))
            self._runtime_guard(self._manifest)
            _require(type(proposal_bytes) is bytes and len(proposal_bytes) <= 65536)
            evidence['proposal_sha256'] = _digest(proposal_bytes)
            p1 = self._gate.proof1
            proposal = json.loads(proposal_bytes.decode('utf-8'),
                                  object_pairs_hook=p1.unique_object,
                                  parse_float=p1.invalid_number,
                                  parse_constant=p1.invalid_number)
            _require(self._gate.valid_proposal(proposal))
            token = self._installation_access()
            self._enforcement(token)
            base = '/repos/' + REPO
            def current():
                ref = self._call(token, 'GET', base + '/git/ref/heads/proof6-authority')
                _require(ref['ref'] == REF and ref['object']['type'] == 'commit')
                return _sha(ref['object']['sha'])
            from journal import Journal
            self._journal = Journal(self)
            self._journal.recover(current, lambda item: print('PROOF6_ADMISSION ' + _canonical(item).decode(), flush=True))
            journal_binding = self._journal.operation_binding(proposal_bytes, proof_operation)
            if proof_operation:
                evidence['consumed_record'] = self._journal.consume(journal_binding)
            old = current()
            evidence['old_sha'] = old
            comparison = self._call(token, 'GET', base + '/compare/' + BASELINE + '...' + old)
            _require(comparison['status'] in ('identical', 'ahead'))
            commit = self._call(token, 'GET', base + '/git/commits/' + old)
            tree = self._call(token, 'GET', base + '/git/trees/' + _sha(commit['tree']['sha']))
            _require(tree['truncated'] is False and len(tree['tree']) == 1)
            entry = tree['tree'][0]
            _require(entry['path'] == 'history.json' and entry['type'] == 'blob'
                     and entry['mode'] == '100644')
            blob = self._call(token, 'GET', base + '/git/blobs/' + _sha(entry['sha']))
            _require(blob['encoding'] == 'base64')
            history = json.loads(base64.b64decode(blob['content']).decode('utf-8'),
                                 object_pairs_hook=p1.unique_object,
                                 parse_float=p1.invalid_number,
                                 parse_constant=p1.invalid_number)
            decision = self._gate.decide(history, proposal)
            evidence['gate'] = decision
            if decision['decision'] != 'ALLOW':
                evidence['result'] = 'REJECTED'
                return evidence
            candidate = {'version': 1, 'events': history['events'] + [decision['candidate_event']]}
            content = base64.b64encode(p1.canonical(candidate)).decode('ascii')
            made_blob = self._call(token, 'POST', base + '/git/blobs',
                                   {'content': content, 'encoding': 'base64'})
            evidence['candidate_blob'] = _sha(made_blob['sha'])
            made_tree = self._call(token, 'POST', base + '/git/trees', {'tree': [
                {'path': 'history.json', 'mode': '100644', 'type': 'blob',
                 'sha': _sha(made_blob['sha'])}]})
            evidence['candidate_tree'] = _sha(made_tree['sha'])
            made_commit = self._call(token, 'POST', base + '/git/commits', {
                'message': 'Proof-6 transition ' + evidence['proposal_sha256'],
                'tree': _sha(made_tree['sha']), 'parents': [old]})
            new = _sha(made_commit['sha'])
            evidence['candidate_commit'] = new
            pending = self._journal.begin(journal_binding, old, new, decision)
            evidence['pending_record'] = pending
            if proof_operation == 'D02_PRE_SEND_STOP':
                _require(current() == old)
                evidence['terminal_record'] = self._journal.finish(pending, old, 'UNARMED')
                evidence.update(result='ERROR', phase='D02_AFTER_ALLOW_BEFORE_TRANSPORT')
                return evidence
            self._enforcement(token)
            self._runtime_guard(self._manifest)
            _require(current() == old)
            self._journal.arm(pending)
            evidence['send_armed_record'] = self._journal.head
            self._journal.take_send(new)
            self._transport_candidate = new
            if proof_operation == 'D03_REVOKE_CURRENT_TOKEN':
                self._revoke_current_token(token, evidence)
            # A single-parent child of old plus force=false rejects a competing
            # sibling winner. No rebase, merge, force, stale retry, or fallback.
            evidence['update_attempted'] = True
            evidence['remote_outcome'] = 'unknown'
            evidence['result'] = 'INDETERMINATE'
            # Non-secret write-ahead receipt survives loss of the response.
            print('PROOF6_PENDING ' + _canonical(evidence).decode('ascii'), flush=True)
            updated = self._patch(token, new, proof_operation == 'D07_DROP_PATCH_RESPONSE', evidence)
            _require(updated['ref'] == REF and updated['object']['sha'] == new)
            _require(current() == new)
            evidence['terminal_record'] = self._journal.finish(pending, new, 'CANDIDATE_OBSERVED')
            evidence.update(result='COMMITTED', new_sha=new, remote_outcome='committed')
            return evidence
        except urllib.error.HTTPError as exc:
            # Only a final response observed inside the actual PATCH can justify
            # rejection. A failing journal/GET request is not authority rejection.
            if (evidence['update_attempted'] and evidence.get('http_status') == exc.code
                    and exc.code in (400, 401, 403, 404, 409, 422)
                    and evidence.get('github_request_id')):
                try:
                    _require(current() == old)
                    evidence['terminal_record'] = self._journal.finish(
                        pending, old, 'FINAL_REJECTION', exc.code, evidence['github_request_id'])
                    evidence.update(result='ERROR', remote_outcome='explicit_rejection')
                except Exception:
                    pass  # Revoked token/log loss cannot erase the armed PENDING.
            return evidence
        except Exception:
            # Never emit exception strings, HTTP bodies, headers, subprocess
            # streams, key material, or tokens. A lost PATCH response is unknown,
            # not evidence of an unchanged ref. Reconciliation is read-only.
            return evidence
