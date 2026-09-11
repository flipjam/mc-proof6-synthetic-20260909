"""Exact D03 PATCH receipt; Actions supports resolution, never journal membership."""
import os
import re
import subprocess

from writer import REPO, REPO_ID, REF, _canonical, _digest, _require

MARKER = 'PROOF6_D03_FINAL_REJECTION '
STEP = 'Verify setup or commit one gated transition'
RUNTIME = 'proof6-writer-runtime-r3d'
WORKFLOW = '.github/workflows/proof6-writer.yml'


def expected(journal, pending):
    from proof_control import plan
    p = journal.pending[pending]
    b = p['binding']
    _require(b['operation'] == 'D03_REVOKE_CURRENT_TOKEN'
             and pending in journal.armed and pending not in journal.resolved)
    arms = [sha for sha, row in journal.rows
            if row['type'] == 'SEND_ARMED' and row['pending'] == pending]
    _require(len(arms) == 1)
    entry = plan()[0]['faults'][b['operation']]
    return dict(schema='PROOF6_D03_FINAL_REJECTION_V1', repository=REPO,
                repository_id=REPO_ID, binding=b, operation_id=_digest(_canonical(b)),
                pending=pending, send_armed=arms[0], gate_sha256=p['gate_sha256'],
                proposal_id=entry['proposal']['proposal_id'],
                plan_entry_sha256=_digest(_canonical(entry)), old=p['old'], candidate=p['candidate'],
                method='PATCH', target='/repos/' + REPO + '/git/refs/heads/proof6-authority',
                ref=REF, force=False, response_class='FINAL_REJECTION', status=401,
                transmission_completed=True, response_consumed=True, revocation_status=204)


def emit(journal, pending, evidence):
    # Called only after the real HTTPS connection returned the expected rejection.
    _require(evidence['token_revocation_confirmed'] is True
             and evidence['token_revocation_status'] == 204
             and evidence['request_transmission_completed'] is True
             and evidence['response_consumed'] is True and evidence['http_status'] == 401
             and re.fullmatch('[A-Za-z0-9:-]{1,128}', evidence['github_request_id']))
    receipt = expected(journal, pending)
    receipt['request_id'] = evidence['github_request_id']
    print(MARKER + _canonical(receipt).decode('ascii'), flush=True)


def _logs(run_id, job_id):
    # Only the fresh invocation's read-only workflow token; never the App token.
    token = os.environ.get('GH_TOKEN', '')
    _require(bool(token))
    result = subprocess.run(
        ['/usr/bin/gh', 'run', 'view', str(run_id), '--attempt', '1', '--job', str(job_id),
         '--repo', REPO, '--log'], check=True, capture_output=True, text=True, timeout=60,
        env={'GH_TOKEN': token, 'GH_HOST': 'github.com', 'PATH': '/usr/bin:/bin',
             'HOME': '/tmp', 'GH_PROMPT_DISABLED': '1', 'GH_PAGER': 'cat'})
    _require(len(result.stdout) <= 2_000_000)
    return result.stdout


def recover(journal, pending):
    # There is no receipt/run argument. The protected operation is the only root.
    from actions_runtime import get
    from journal import parse
    want = expected(journal, pending)
    b = want['binding']
    _require(journal.writer._receipt_binding['run_id'] != b['run_id'])
    base = 'repos/' + REPO + '/actions/runs/' + str(b['run_id']) + '/attempts/1'
    run = get(base)
    _require(run['id'] == b['run_id'] and run['run_attempt'] == 1
             and run['repository']['id'] == REPO_ID and run['repository']['full_name'] == REPO
             and run['head_repository']['id'] == REPO_ID
             and run['head_sha'] == b['runtime_sha'] and run['head_branch'] == RUNTIME
             and run['path'] == WORKFLOW and run['event'] == 'workflow_dispatch'
             and run['status'] == 'completed' and run['conclusion'] == 'failure'
             and run['actor']['id'] == b['caller']['id']
             and run['actor']['login'] == b['caller']['login']
             and run['triggering_actor']['id'] == b['caller']['id'])
    jobs = get(base + '/jobs?per_page=100')
    _require(jobs['total_count'] == 1 and len(jobs['jobs']) == 1)
    job = jobs['jobs'][0]
    _require(type(job['id']) is int and job['id'] > 0 and job['run_id'] == b['run_id']
             and job['run_attempt'] == 1 and job['head_sha'] == b['runtime_sha']
             and job['name'] == 'writer' and job['status'] == 'completed'
             and job['conclusion'] == 'failure')
    steps = [step for step in job['steps'] if step['name'] == STEP]
    _require(len(steps) == 1 and steps[0]['status'] == 'completed' and steps[0]['conclusion'] == 'failure')
    lines = [line for line in _logs(b['run_id'], job['id']).splitlines() if MARKER in line]
    _require(len(lines) == 1)
    # gh's exact job/step/timestamp prefix is required; echoed input is not a receipt.
    match = re.fullmatch(r'writer\t' + re.escape(STEP)
                         + r'\t\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z '
                         + re.escape(MARKER) + r'(\{.*\})', lines[0])
    _require(match is not None)
    receipt = parse(match[1].encode('ascii'))
    request_id = receipt.get('request_id')
    _require(type(request_id) is str and re.fullmatch('[A-Za-z0-9:-]{1,128}', request_id))
    want['request_id'] = request_id
    # Canonical bytes also reject bool/int substitutions and extra fields.
    _require(_canonical(receipt) == _canonical(want))
    return request_id
