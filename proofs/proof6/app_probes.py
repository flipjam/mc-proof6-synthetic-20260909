"""F02/F10 only, inside consumed D02. No public target/payload interface."""
import json
import re
import urllib.error

from writer import REPO, _canonical, _digest, _require, _sha

RUNTIME = 'refs/heads/proof6-writer-runtime-r3i'
BASE = '/repos/' + REPO


def _negative(error):
    # Preserve only bounded non-secret provider evidence. A simulated response
    # never proves the live permission claim; independent review is mandatory.
    try:
        raw = error.read(4097)
    finally:
        error.close()
    _require(len(raw) <= 4096 and error.code in (403, 422))
    body = json.loads(raw)
    message = body.get('message')
    _require(message in ('Resource not accessible by integration',
                         'Repository rule violations found for ' + RUNTIME + '.'))
    request_id = error.headers.get('x-github-request-id')
    _require(type(request_id) is str and re.fullmatch('[A-Za-z0-9:-]{1,128}', request_id))
    _require(error.headers.get('retry-after') is None and error.headers.get('x-ratelimit-remaining') != '0')
    return dict(status=error.code, message=message, request_id=request_id,
                body_sha256=_digest(raw), independent_live_review_required=True)


def run_d02_probes(writer):
    journal = writer._journal
    _require('D02_PRE_SEND_STOP' in journal.used)
    matches = [p for p in journal.pending.values() if p['binding']['operation'] == 'D02_PRE_SEND_STOP']
    _require(len(matches) == 1 and matches[0]['binding']['run_id'] == writer._receipt_binding['run_id'])
    pending = next(k for k, v in journal.pending.items() if v is matches[0])
    _require(pending in journal.resolved and journal.terminals[pending][2]['evidence'] == 'UNARMED')
    writer._runtime_guard(writer._manifest)
    writer._enforcement(writer._installation_token)
    writer._last_evidence['app_probe_result'] = 'FAIL'
    token = writer._installation_token
    # Meaningful modification of the fixed authority update rule. Never accept
    # a success as harmless; stop immediately with no second probe or rollback.
    rule = dict(name='proof6-app-only-update', target='branch', enforcement='disabled',
                conditions={'ref_name': {'include': ['refs/heads/proof6-authority'], 'exclude': []}},
                rules=[{'type': 'update'}], bypass_actors=[{
                    'actor_id': 4893415, 'actor_type': 'Integration', 'bypass_mode': 'always'}])
    from proof_control import plan
    _require(plan()[0]['fixed_app_probes']['F02']['payload'] == rule)
    try:
        writer._call(token, 'PUT', BASE + '/rulesets/22725076', rule)
    except urllib.error.HTTPError as error:
        f02 = _negative(error)
    else:
        raise ValueError('F02_UNEXPECTED_SUCCESS_TERMINAL_PROOF_FAILURE')
    writer._enforcement(token)
    writer._runtime_guard(writer._manifest)
    frozen = writer._manifest['runtime']['sha']
    ref = writer._call(token, 'GET', BASE + '/git/ref/heads/proof6-writer-runtime-r3i')
    _require(ref['ref'] == RUNTIME and ref['object']['sha'] == frozen)
    commit = writer._call(token, 'GET', BASE + '/git/commits/' + _sha(frozen))
    _require(commit['sha'] == frozen)
    child = writer._call(token, 'POST', BASE + '/git/commits', {
        'message': 'Proof6 R3i F10 fixed runtime fast-forward negative probe',
        'tree': _sha(commit['tree']['sha']), 'parents': [frozen]})
    candidate = _sha(child['sha'])
    _require(candidate != frozen)
    try:
        writer._call(token, 'PATCH', BASE + '/git/refs/heads/proof6-writer-runtime-r3i',
                     {'sha': candidate, 'force': False})
    except urllib.error.HTTPError as error:
        f10 = _negative(error)
    else:
        raise ValueError('F10_UNEXPECTED_SUCCESS_TERMINAL_PROOF_FAILURE')
    writer._runtime_guard(writer._manifest)
    ref = writer._call(token, 'GET', BASE + '/git/ref/heads/proof6-writer-runtime-r3i')
    _require(ref['ref'] == RUNTIME and ref['object']['sha'] == frozen)
    writer._last_evidence.update(app_probe_result='NEGATIVE_RESPONSES_RECORDED',
        app_probes=dict(F02=dict(f02, target=22725076, payload_sha256=_digest(_canonical(rule))),
                       F10=dict(f10, old=frozen, candidate=candidate, force=False)))
