"""Unactivated Proof-6 writer candidate for a future isolated owner runtime.

Only commit_transition(proposal_bytes) is a client operation. No CLI, HTTP
listener, environment-token fallback, retries, or runtime manifest is shipped.
Private constructor arguments belong to the trusted runtime, never a request.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time
import urllib.request
import urllib.error
import diagnostics as dia
from ruleset_view import visible

ROOT = Path(__file__).resolve().parents[2]
REPO = 'flipjam/mc-proof6-synthetic-20260909'
REPO_ID = 1363510385
REF = 'refs/heads/proof6-authority'
BASELINE = 'ff8174ff7081e6b54e7b77c80958007ac4cd497e'
APP_ID = 4893415
INSTALLATION = 160504789
PERMISSIONS = {'contents': 'write', 'metadata': 'read'}
CONFIG_DIGEST = 'b5d40e5549e94a1240a179b3e8b4fd883304d1192273ae28e3dbc84292ee7aa2'
VISIBLE_CONFIG_DIGEST = 'ba09309c64e7f683ca00b9f1f394495e9b1b56b07ee850e538096518dd3ccd86'
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


_PEM_HEADERS = {
    '-----BEGIN RSA PRIVATE KEY-----': '-----END RSA PRIVATE KEY-----',
    '-----BEGIN PRIVATE KEY-----': '-----END PRIVATE KEY-----',
}
_PEM_FOOTERS = set(_PEM_HEADERS.values())


def _pem_structure(path):
    """Check only safe PEM structure; never return or print key material."""
    try:
        text = path.read_bytes().decode('ascii')
    except UnicodeDecodeError:
        dia.fail('DIA03A', 'PEM_HEADER_INVALID')
    except OSError:
        dia.fail('DIA03A', 'OS_OPERATION_FAILED')
    if '\\n' in text or '\\r' in text:
        dia.fail('DIA03A', 'PEM_LITERAL_BACKSLASH_N')
    if '\r' in text.replace('\r\n', ''):
        dia.fail('DIA03A', 'PEM_HEADER_INVALID')
    lines = text.replace('\r\n', '\n').split('\n')
    first = 0
    last = len(lines) - 1
    while first <= last and lines[first] == '':
        first += 1
    while last >= first and lines[last] == '':
        last -= 1
    if first > last:
        dia.fail('DIA03A', 'PEM_HEADER_INVALID')
    if any('ENCRYPTED' in line for line in lines[first:last + 1]):
        dia.fail('DIA03A', 'PEM_ENCRYPTED_KEY_UNSUPPORTED')
    header = lines[first]
    if header not in _PEM_HEADERS:
        if any(line in _PEM_HEADERS for line in lines[first + 1:last + 1]):
            dia.fail('DIA03A', 'PEM_UNEXPECTED_SURROUNDING_TEXT')
        dia.fail('DIA03A', 'PEM_HEADER_INVALID')
    if first != 0 and any(line != '' for line in lines[:first]):
        dia.fail('DIA03A', 'PEM_UNEXPECTED_SURROUNDING_TEXT')
    footer = lines[last]
    if footer != _PEM_HEADERS[header]:
        if footer in _PEM_FOOTERS:
            dia.fail('DIA03A', 'PEM_HEADER_FOOTER_MISMATCH')
        dia.fail('DIA03A', 'PEM_FOOTER_INVALID')
    if last != len(lines) - 1 and any(line != '' for line in lines[last + 1:]):
        dia.fail('DIA03A', 'PEM_UNEXPECTED_SURROUNDING_TEXT')
    if not any(line != '' for line in lines[first + 1:last]):
        dia.fail('DIA03A', 'PEM_BODY_MISSING')
    dia.ok('DIA03A_PEM_STRUCTURE_OK')


def _openssl(path, openssl, args):
    try:
        return subprocess.run([str(openssl), *args, str(path)],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        dia.fail('DIA03B', 'OPENSSL_EXECUTION_FAILED')


def _private_key_diagnostics(path, openssl):
    """Run parse, integrity, and fixed-byte signing checks with safe markers."""
    _pem_structure(path)
    dia.start('DIA03B')
    parsed = _openssl(path, openssl, ['pkey', '-noout', '-passin', 'pass:'])
    if parsed.returncode != 0:
        dia.fail('DIA03B', 'OPENSSL_KEY_PARSE_FAILED')
    checked = _openssl(path, openssl, ['pkey', '-check', '-noout', '-passin', 'pass:'])
    if checked.returncode != 0:
        dia.fail('DIA03B', 'OPENSSL_KEY_CHECK_FAILED')
    dia.ok('DIA03B_OPENSSL_KEY_CHECK_OK')
    dia.start('DIA03C')
    try:
        signed = subprocess.run(
            [str(openssl), 'dgst', '-sha256', '-sign', str(path)],
            input=b'proof6-diagnostic-sign-test-v1', stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        dia.fail('DIA03C', 'OPENSSL_SIGN_FAILED')
    if signed.returncode != 0:
        dia.fail('DIA03C', 'OPENSSL_SIGN_FAILED')
    dia.ok('DIA03C_PRIVATE_KEY_SIGN_OK')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('REDIRECT_REFUSED')


class _Writer:
    def __init__(self, *, frozen_manifest, private_key_path, openssl_path, runtime_guard):
        # The eventual owner-only launcher must supply these from immutable
        # server configuration, not from client fields or environment variables.
        # This code cannot establish OS credential isolation on its own.
        self._key = Path(private_key_path)
        self._openssl = Path(openssl_path)
        _require(self._key.is_absolute() and self._openssl.is_absolute())
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
        _require(m['contract_commit'] == 'bac6531426d32361ad99391e84be412ea3f4bcc4'
                 and m['revision'] == 2 and m['frozen'] is True
                 and m['repository_id'] == REPO_ID and m['repository'] == REPO
                 and m['ref'] == REF and m['baseline_commit'] == BASELINE
                 and m['app_id'] == APP_ID and m['installation_id'] == INSTALLATION
                 and m['configuration_sha256'] == CONFIG_DIGEST
                 and m['authority_visible_sha256'] == VISIBLE_CONFIG_DIGEST
                 and m['accepted_code_sha256'] == CODE)
        _require(m['writer_sha256'] == self._writer_digest)

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

    def _token(self):
        _private_key_diagnostics(self._key, self._openssl)
        def b64(raw):
            return base64.urlsafe_b64encode(raw).rstrip(b'=')
        now = int(time.time())
        signing = b64(_canonical({'alg': 'RS256', 'typ': 'JWT'})) + b'.' + b64(
            _canonical({'iat': now - 60, 'exp': now + 540, 'iss': str(APP_ID)}))
        # Key stays in the isolated runtime. Neither key nor JWT is an argument,
        # output, log record, repository file, or ordinary-client credential.
        dia.start('DIA04')
        try:
            signed = subprocess.run(
                [str(self._openssl), 'dgst', '-sha256', '-sign', str(self._key)],
                input=signing, capture_output=True, check=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            dia.fail('DIA04', 'OPENSSL_SIGN_FAILED')
        jwt = (signing + b'.' + b64(signed.stdout)).decode('ascii')
        app = self._call(jwt, 'GET', '/app')
        dia.ok('DIA04_APP_JWT_AUTH_OK')
        dia.start('DIA05')
        _require(app['id'] == APP_ID and app['slug'] == 'mc-proof-6-gate-writer'
                 and app['owner']['login'] == 'flipjam'
                 and app['permissions'] == PERMISSIONS and app['events'] == [])
        dia.ok('DIA05_APP_IDENTITY_OK')
        prefix = '/app/installations/' + str(INSTALLATION)
        dia.start('DIA06')
        install = self._call(jwt, 'GET', prefix)
        dia.ok('DIA06_INSTALLATION_LOOKUP_OK')
        dia.start('DIA07')
        _require(install['id'] == INSTALLATION and install['app_id'] == APP_ID
                 and install['account']['id'] == 10454889
                 and install['permissions'] == PERMISSIONS
                 and install['events'] == []
                 and install['app_slug'] == 'mc-proof-6-gate-writer'
                 and install['repository_selection'] == 'selected'
                 and install['suspended_at'] is None)
        dia.ok('DIA07_INSTALLATION_METADATA_OK')
        # Do not downscope repository selection here: the subsequent list must
        # detect any extra installed repository instead of concealing it.
        dia.start('DIA08')
        issued = self._call(jwt, 'POST', prefix + '/access_tokens', {})
        _require(issued['permissions'] == PERMISSIONS)
        dia.ok('DIA08_INSTALLATION_TOKEN_ISSUED')
        token = issued['token']
        dia.start('DIA09')
        listing = self._call(token, 'GET', '/installation/repositories?per_page=100')
        _require(listing['total_count'] == 1 and len(listing['repositories']) == 1)
        repo = listing['repositories'][0]
        _require(repo['id'] == REPO_ID and repo['full_name'] == REPO
                 and repo['private'] is False)
        dia.ok('DIA09_REPOSITORY_SELECTION_OK')
        return token

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
        token = self._token()
        self._enforcement(token)
        runtime = self._runtime_guard(None)
        dia.ok('DIA13_SETUP_AUTH_VERIFIED')
        return {'result': 'APP_AUTH_SETUP_VERIFIED', 'app_id': APP_ID,
                'installation_id': INSTALLATION, 'repository_id': REPO_ID,
                'permissions': PERMISSIONS, 'runtime': runtime,
                'mutation_attempted': False}

    def commit_transition(self, proposal_bytes):
        evidence = {'result': 'ERROR', 'manifest_sha256': self._manifest_digest,
                    'writer_sha256': self._writer_digest,
                    'accepted_code_sha256': CODE, 'configuration_sha256': CONFIG_DIGEST,
                    'authority_visible_sha256': VISIBLE_CONFIG_DIGEST,
                    'old_sha': None, 'new_sha': None, 'candidate_commit': None,
                    'update_attempted': False, 'remote_outcome': 'not_attempted'}
        try:
            _require(self._manifest is not None)
            self._runtime_guard(self._manifest)
            _require(type(proposal_bytes) is bytes and len(proposal_bytes) <= 65536)
            evidence['proposal_sha256'] = _digest(proposal_bytes)
            p1 = self._gate.proof1
            proposal = json.loads(proposal_bytes.decode('utf-8'),
                                  object_pairs_hook=p1.unique_object,
                                  parse_float=p1.invalid_number,
                                  parse_constant=p1.invalid_number)
            _require(self._gate.valid_proposal(proposal))
            token = self._token()
            self._enforcement(token)
            base = '/repos/' + REPO
            def current():
                ref = self._call(token, 'GET', base + '/git/ref/heads/proof6-authority')
                _require(ref['ref'] == REF and ref['object']['type'] == 'commit')
                return _sha(ref['object']['sha'])
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
            made_tree = self._call(token, 'POST', base + '/git/trees', {'tree': [
                {'path': 'history.json', 'mode': '100644', 'type': 'blob',
                 'sha': _sha(made_blob['sha'])}]})
            made_commit = self._call(token, 'POST', base + '/git/commits', {
                'message': 'Proof-6 transition ' + evidence['proposal_sha256'],
                'tree': _sha(made_tree['sha']), 'parents': [old]})
            new = _sha(made_commit['sha'])
            evidence['candidate_commit'] = new
            self._enforcement(token)
            self._runtime_guard(self._manifest)
            _require(current() == old)
            # A single-parent child of old plus force=false rejects a competing
            # sibling winner. No rebase, merge, force, stale retry, or fallback.
            evidence['update_attempted'] = True
            evidence['remote_outcome'] = 'unknown'
            evidence['result'] = 'INDETERMINATE'
            # Non-secret write-ahead receipt survives loss of the response.
            print('PROOF6_PENDING ' + _canonical(evidence).decode('ascii'), flush=True)
            updated = self._call(token, 'PATCH', base + '/git/refs/heads/proof6-authority',
                                 {'sha': new, 'force': False})
            _require(updated['ref'] == REF and updated['object']['sha'] == new)
            evidence.update(result='COMMITTED', new_sha=new, remote_outcome='committed')
            return evidence
        except urllib.error.HTTPError as exc:
            if evidence['update_attempted'] and exc.code in (400, 401, 403, 404, 409, 422):
                evidence.update(result='ERROR', remote_outcome='explicit_rejection')
            return evidence
        except Exception:
            # Never emit exception strings, HTTP bodies, headers, subprocess
            # streams, key material, or tokens. A lost PATCH response is unknown,
            # not evidence of an unchanged ref. Reconciliation is read-only.
            return evidence
