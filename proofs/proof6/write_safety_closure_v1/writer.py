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

ROOT = Path(__file__).resolve().parents[3]
REPO = 'flipjam/mc-proof6-synthetic-20260909'
REPO_ID = 1363510385
REF = 'refs/heads/proof6-ws-closure-v1-authority'
from common import APP_ID, INSTALLATION, PERMISSIONS
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


def _d03_complete_body(response):
    """One fixed Content-Length response on the D03 connection-close exchange."""
    from d03_rejection import BODY_LIMIT
    lengths = response.headers.get_all('Content-Length', [])
    _require(not response.headers.defects and len(lengths) == 1
             and not response.headers.get_all('Transfer-Encoding', []))
    length = lengths[0].strip(' \t')
    # Bound decimal parsing as well as body allocation. No signs, lists or folds.
    _require(re.fullmatch(r'[0-9]{1,4}', length) is not None)
    declared = int(length)
    _require(declared <= BODY_LIMIT and response.length == declared
             and response.chunked is False and response.fp is not None)
    stream = response.fp
    chunks = []
    remaining = declared
    while remaining:
        chunk = stream.read(remaining)
        _require(type(chunk) is bytes and 0 < len(chunk) <= remaining)
        chunks.append(chunk)
        remaining -= len(chunk)
    # HTTPResponse.read caps at Content-Length and can hide excess bytes. This
    # fixed, non-reused connection requests close; require EOF AFTER the declared
    # length, never use EOF as a substitute for framing. Timeout remains unknown.
    _require(stream.read(1) == b'')
    raw = b''.join(chunks)
    response.close()
    return raw, dict(response_framing='content_length', declared_body_length=declared,
                     consumed_body_length=len(raw), response_complete=True,
                     connection_eof=True)


class _Writer:
    def __init__(self, *, frozen_manifest, installation_token,
                 action_installation_id, action_app_slug, runtime_guard, receipt_binding=None):
        self._last_evidence = None
        self._transport_candidate = None
        self._d03_transport_token = None
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
        from qualification import validate_manifest
        validate_manifest(m, local=True)
        self._baseline = m['baseline_commit']

    def _call(self, token, method, path, body=None):
        _require(path.startswith('/') and not path.startswith('//'))
        observer = getattr(self, '_journal_append_observer', None)
        if method != 'PATCH' or path != '/repos/' + REPO + '/git/refs/heads/proof6-ws-closure-v1-journal':
            observer = None
        request = urllib.request.Request(
            'https://api.github.com' + path,
            data=None if body is None else _canonical(body), method=method,
            headers={'Authorization': 'Bearer ' + token,
                     'Accept': 'application/vnd.github+json',
                     'Content-Type': 'application/json',
                     'User-Agent': 'mc-proof6-gate-writer',
                     'X-GitHub-Api-Version': '2022-11-28'})
        try:
            with self._http.open(request, timeout=30) as response:
                if observer is not None:
                    observer.http_response(response.status, response.headers.get('x-github-request-id'))
                raw = response.read(2_000_001)
        except urllib.error.HTTPError as error:
            if observer is not None:
                observer.http_response(error.code, error.headers.get('x-github-request-id'))
            raise
        _require(len(raw) <= 2_000_000)
        value = json.loads(raw)
        if observer is not None:
            observer.parsed_response()
        return value

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

    def _patch(self, new, drop_response, evidence):
        d03 = evidence.get('proof_operation') == 'D03_REMOTE_REJECTION'
        # Credential roles are fixed, never a public or generic transport argument.
        if d03:
            token, self._d03_transport_token = self._d03_transport_token, None
            _require(bool(token) and token != self._installation_token)
        else:
            token = self._installation_token
        permit, self._transport_candidate = self._transport_candidate, None
        _require(permit is not None and permit == _sha(new))
        path = '/repos/' + REPO + '/git/refs/heads/proof6-ws-closure-v1-authority'
        conn = http.client.HTTPSConnection('api.github.com', timeout=30)
        try:
            conn.request('PATCH', path, body=_canonical({'sha': new, 'force': False}),
                         headers={'Authorization': 'Bearer ' + token,
                                  'Accept': 'application/vnd.github+json',
                                  'Content-Type': 'application/json',
                                  'User-Agent': 'mc-proof6-gate-writer',
                                  'X-GitHub-Api-Version': '2022-11-28',
                                  **({'Connection': 'close'} if d03 else {})})
            evidence['request_transmission_completed'] = True
            if drop_response:
                evidence['response_consumed'] = False
                evidence['response_path_discarded'] = True
                raise ConnectionError('PROOF_RESPONSE_DROPPED')
            response = conn.getresponse()
            evidence['http_status'] = response.status
            request_id = response.getheader('x-github-request-id', None)
            if request_id and re.fullmatch('[A-Za-z0-9:-]{1,128}', request_id):
                evidence['github_request_id'] = request_id
            if d03:
                raw, completion = _d03_complete_body(response)
                evidence['response_consumed'] = True
                # Internal return only. Unclassified response bodies never enter logs.
                return dict(raw=raw, completion=completion, request_id=request_id,
                            rate_limit_remaining=response.getheader('x-ratelimit-remaining', None),
                            retry_after=response.getheader('retry-after', None))
            evidence['response_consumed'] = True
            if response.status >= 400:
                raise urllib.error.HTTPError('https://api.github.com' + path,
                                             response.status, 'PATCH_REJECTED', {}, None)
            raw = response.read(2_000_001)
            _require(200 <= response.status < 300 and len(raw) <= 2_000_000)
            return json.loads(raw)
        finally:
            conn.close()

    def _enforcement(self, token):
        for expected in self._manifest['authority_rulesets']:
            actual = self._call(token, 'GET', '/repos/' + REPO + '/rulesets/' + str(expected['id']))
            _require(visible(actual) == visible(expected))
            if 'bypass_actors' in actual:
                _require(actual['bypass_actors'] == expected['bypass_actors'])

    def _current_authority(self):
        ref = self._call(self._installation_token, 'GET',
                         '/repos/' + REPO + '/git/ref/heads/proof6-ws-closure-v1-authority')
        _require(ref['ref'] == REF and ref['object']['type'] == 'commit')
        return _sha(ref['object']['sha'])

    def _history(self, sha):
        base = '/repos/' + REPO
        token = self._installation_token
        commit = self._call(token, 'GET', base + '/git/commits/' + _sha(sha))
        _require(commit['sha'] == sha)
        tree_sha = _sha(commit['tree']['sha'])
        tree = self._call(token, 'GET', base + '/git/trees/' + tree_sha)
        _require(tree['sha'] == tree_sha and tree['truncated'] is False and len(tree['tree']) == 1)
        entry = tree['tree'][0]
        _require(entry['path'] == 'history.json' and entry['type'] == 'blob' and entry['mode'] == '100644')
        blob_sha = _sha(entry['sha'])
        blob = self._call(token, 'GET', base + '/git/blobs/' + blob_sha)
        _require(blob['sha'] == blob_sha and blob['encoding'] == 'base64')
        raw = base64.b64decode(blob['content'], validate=False)
        _require(len(raw) <= 2_000_000 and hashlib.sha1(
            b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == blob_sha)
        p1 = self._gate.proof1
        history = json.loads(raw.decode('utf-8'), object_pairs_hook=p1.unique_object,
                             parse_float=p1.invalid_number, parse_constant=p1.invalid_number)
        state = p1.reconstruct(history)
        if sha == self._baseline:
            _require(state['state_sha256'] == self._manifest['baseline_state_sha256'])
        return commit, history, state

    def _validate_transition(self, pending):
        """Audit protected history with the accepted pure gate; never resume it."""
        _, history, current = self._history(pending['old'])
        child, candidate, _ = self._history(pending['candidate'])
        _require(child['parents'] == [{'sha': pending['old']}] or
                 (len(child['parents']) == 1 and child['parents'][0]['sha'] == pending['old']))
        _require(len(candidate['events']) == len(history['events']) + 1)
        event = candidate['events'][-1]
        prefix = 'proof2:proposal:'
        _require(event['id'].startswith(prefix))
        state = current['state']
        proposal = dict(proposal_id=event['id'][len(prefix):], project=state['project'],
                        subject=state['subject'], expected_state_sha256=current['state_sha256'],
                        loop_id=state['loop']['id'], expected_baton=state['loop']['baton'], action='ADVANCE_ROADMAP')
        _require(_digest(_canonical(proposal)) == pending['binding']['proposal_sha256'])
        decision = self._gate.decide(history, proposal)
        _require(decision['decision'] == 'ALLOW' and _digest(_canonical(decision)) == pending['gate_sha256']
                 and candidate == {'version': 1, 'events': history['events'] + [decision['candidate_event']]})

    def recover_only(self):
        """Qualified frozen empty request. No authority transport or send permit."""
        self._last_evidence = dict(result='BLOCKED', update_attempted=False,
            remote_outcome='not_attempted', journal_completion_attempted=False,
            admission='BLOCKED', historical_invocation_reclassified=False)
        self._runtime_guard(self._manifest)
        token = self._installation_access()
        self._enforcement(token)
        from journal import Journal
        journal = Journal(self)
        current = self._current_authority
        expected, pending = journal.reconcile(current)
        if pending is not None and journal.pending[pending]['binding']['operation'] == 'D07_DROP_PATCH_RESPONSE':
            from sibling_canary import recover_d07
            expected = recover_d07(self)
        else:
            expected = journal.recover(current, lambda item: print(
                'PROOF6_RECOVERY ' + _canonical(item).decode(), flush=True))
        return dict(result='RECOVERY_CONFIRMED', authority_sha=expected,
                    update_attempted=False, remote_outcome='not_attempted',
                    admission='CONFIRMED', historical_invocation_reclassified=False)

    def commit_transition(self, proposal_bytes, proof_operation=''):
        evidence = {'result': 'ERROR', 'manifest_sha256': self._manifest_digest,
                    'writer_sha256': self._writer_digest,
                    'accepted_code_sha256': CODE, 'configuration_sha256': self._manifest['configuration_sha256'],
                    'authority_visible_sha256': self._manifest['authority_visible_sha256'],
                    'app_id': APP_ID, 'app_slug': 'mc-proof-6-gate-writer',
                    'installation_id': INSTALLATION,
                    'token_permissions': PERMISSIONS,
                    'action': {'repository': ACTION_REPOSITORY, 'commit': ACTION_COMMIT},
                    'old_sha': None, 'new_sha': None, 'candidate_commit': None,
                    'update_attempted': False, 'remote_outcome': 'not_attempted'}
        evidence.update(self._receipt_binding)
        if proof_operation == 'D03_REMOTE_REJECTION':
            evidence['d03_result'] = 'FAIL'
        # Keep the same live evidence object across all exception boundaries.
        # After send becomes possible no outer handler may emit a false no-update receipt.
        self._last_evidence = evidence
        try:
            _require(self._manifest is not None)
            from proof_control import FAULTS, plan, validate_payload
            _require(type(proof_operation) is str and proof_operation in ('', *FAULTS))
            validate_payload(proposal_bytes, proof_operation, self._manifest)
            _require(self._receipt_binding.get('proof_operation') == proof_operation
                     and self._receipt_binding.get('proof_plan_sha256') == plan()[1])
            self._runtime_guard(self._manifest)
            _require(type(proposal_bytes) is bytes and len(proposal_bytes) <= 65536)
            evidence['proposal_sha256'] = _digest(proposal_bytes)
            p1 = self._gate.proof1
            proposal = json.loads(proposal_bytes.decode('utf-8'),
                                  object_pairs_hook=p1.unique_object,
                                  parse_float=p1.invalid_number,
                                  parse_constant=p1.invalid_number)
            _require(self._gate.valid_proposal(proposal))
            # Bind normative proposal data, so complete recovery can reconstruct
            # its identity from the exact accepted candidate/history.
            proposal_bytes = _canonical(proposal)
            evidence['proposal_sha256'] = _digest(proposal_bytes)
            token = self._installation_access()
            self._enforcement(token)
            base = '/repos/' + REPO
            def current():
                ref = self._call(token, 'GET', base + '/git/ref/heads/proof6-ws-closure-v1-authority')
                _require(ref['ref'] == REF and ref['object']['type'] == 'commit')
                return _sha(ref['object']['sha'])
            from journal import Journal
            self._journal = Journal(self)
            reconciled, missing = self._journal.reconcile(current)
            _require(missing is None)
            if proof_operation:
                _require(proof_operation not in self._journal.used)
                if proof_operation == 'D07_DROP_PATCH_RESPONSE':
                    _require(self._journal.used == {'D03_REMOTE_REJECTION'}
                             and len(self._journal.terminals) == 1)
            else:
                _require(self._journal.used == set(FAULTS)
                         and len(self._journal.terminals) == 2
                         and all(p['binding']['operation'] for p in self._journal.pending.values()))
                d07 = [p for p, r in self._journal.pending.items()
                       if r['binding']['operation'] == 'D07_DROP_PATCH_RESPONSE']
                _require(len(d07) == 1 and self._journal.terminals[d07[0]][2]['disposition'] == 'COMMITTED')
            journal_binding = self._journal.operation_binding(proposal_bytes, proof_operation)
            old = current()
            _require(old == reconciled)
            evidence['old_sha'] = old
            _, history, _ = self._history(old)
            decision = self._gate.decide(history, proposal)
            evidence['gate'] = decision
            if decision['decision'] != 'ALLOW':
                evidence['result'] = 'REJECTED'
                return evidence
            if proof_operation:
                evidence['consumed_record'] = self._journal.consume(journal_binding)
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
            self._enforcement(token)
            self._runtime_guard(self._manifest)
            _require(current() == old)
            self._journal.arm(pending)
            evidence['send_armed_record'] = self._journal.head
            if proof_operation == 'D03_REMOTE_REJECTION':
                from d03_job_token import bind
                self._d03_transport_token, evidence['d03_credential'] = bind(self)
            self._journal.take_send(new)
            self._transport_candidate = new
            # A single-parent child of old plus force=false rejects a competing
            # sibling winner. No rebase, merge, force, stale retry, or fallback.
            evidence['update_attempted'] = True
            evidence['remote_outcome'] = 'unknown'
            evidence['result'] = 'INDETERMINATE'
            # Non-secret write-ahead receipt survives loss of the response.
            print('PROOF6_PENDING ' + _canonical(evidence).decode('ascii'), flush=True)
            updated = self._patch(new, proof_operation == 'D07_DROP_PATCH_RESPONSE', evidence)
            if proof_operation == 'D03_REMOTE_REJECTION':
                from d03_rejection import body, receipt
                evidence['d03_result'] = 'FAIL'
                observed = current()
                if observed == new:
                    evidence['terminal_record'] = self._journal.finish(pending, new, 'CANDIDATE_OBSERVED')
                    evidence.update(result='COMMITTED', new_sha=new, remote_outcome='committed')
                    return evidence
                _require(observed == old and evidence['http_status'] == 403)
                body(updated['raw'])
                response = dict(transmitted=True, consumed=True, status=evidence['http_status'],
                                request_id=updated['request_id'], body=updated['raw'].decode('utf-8'),
                                body_sha256=_digest(updated['raw']),
                                rate_limit_remaining=updated['rate_limit_remaining'], retry_after=updated['retry_after'],
                                **updated['completion'])
                # Recheck enforcement/runtime with the normal App/launcher guards.
                self._enforcement(token)
                self._runtime_guard(self._manifest)
                exact = receipt(self._journal, pending, dict(d03_response=response,
                    d03_enforcement_unchanged=True, d03_credential=evidence['d03_credential']))
                evidence['d03_response'] = response
                evidence['d03_enforcement_unchanged'] = True
                observed = current()
                if observed == new:
                    evidence['terminal_record'] = self._journal.finish(pending, new, 'CANDIDATE_OBSERVED')
                    evidence.update(result='COMMITTED', new_sha=new, remote_outcome='committed')
                    return evidence
                _require(observed == old)
                evidence['terminal_record'] = self._journal.finish(
                    pending, old, 'FINAL_REJECTION', 403, response['request_id'], d03=exact)
                evidence.update(result='ERROR', remote_outcome='explicit_rejection', d03_result='PASS')
                return evidence
            _require(updated['ref'] == REF and updated['object']['sha'] == new)
            _require(current() == new)
            evidence['terminal_record'] = self._journal.finish(pending, new, 'CANDIDATE_OBSERVED')
            evidence.update(result='COMMITTED', new_sha=new, remote_outcome='committed')
            return evidence
        except urllib.error.HTTPError as exc:
            # Only a final response observed inside the actual PATCH can justify
            # rejection. A failing journal/GET request is not authority rejection.
            if (proof_operation != 'D03_REMOTE_REJECTION' and evidence['update_attempted']
                    and evidence.get('http_status') == exc.code
                    and exc.code in (400, 401, 403, 404, 409, 422)
                    and evidence.get('github_request_id')):
                try:
                    _require(current() == old)
                    evidence['terminal_record'] = self._journal.finish(
                        pending, old, 'FINAL_REJECTION', exc.code, evidence['github_request_id'])
                    evidence.update(result='ERROR', remote_outcome='explicit_rejection')
                except Exception:
                    pass  # Finalization failure cannot erase the armed PENDING.
            return evidence
        except Exception:
            # Never emit exception strings, HTTP bodies, headers, subprocess
            # streams, key material, or tokens. A lost PATCH response is unknown,
            # not evidence of an unchanged ref. Reconciliation is read-only.
            return evidence
