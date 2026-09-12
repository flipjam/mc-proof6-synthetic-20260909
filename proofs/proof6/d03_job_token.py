"""D03 only: the current hosted worker's server-supplied permission boundary."""
import json
import os
from pathlib import Path
import re

from writer import REPO, REPO_ID, _canonical, _require

SOURCE = 'github.token/current-worker-job-message/v1'
PERMISSIONS = {'Actions': 'read', 'Contents': 'read', 'Metadata': 'read'}
RUNTIME = 'refs/heads/proof6-writer-runtime-r3i'
WORKFLOW = REPO + '/.github/workflows/proof6-writer.yml@' + RUNTIME


def _worker_log():
    # Only our actual Runner.Worker ancestor and its already-open diagnostic.
    # No caller path, environment override, retained Actions log or API token.
    pid = os.getppid()
    for _ in range(32):
        proc = Path('/proc') / str(pid)
        exe = (proc / 'exe').resolve(strict=True)
        if exe.name == 'Runner.Worker':
            expected = exe.parent.parent / '_diag'
            logs = []
            for fd in (proc / 'fd').iterdir():
                try:
                    target = fd.resolve(strict=True)
                except OSError:
                    continue
                if target.parent == expected and re.fullmatch(r'Worker_[A-Za-z0-9_.-]+\.log', target.name):
                    logs.append(fd)
            _require(len(logs) == 1)
            with logs[0].open('rb') as stream:
                raw = stream.read(2_000_001)
            _require(len(raw) <= 2_000_000)
            return raw
        parents = re.findall(r'^PPid:\s+(\d+)$', (proc / 'status').read_text(), re.M)
        _require(len(parents) == 1 and int(parents[0]) > 1)
        pid = int(parents[0])
    raise ValueError('D03_CURRENT_WORKER_UNAVAILABLE')


def _permission_evidence(raw, binding):
    # Runner initializes its secret masker BEFORE recording this startup message.
    # Never retain, hash, print or return the whole diagnostic/message. Only the
    # non-secret allowlist below enters protected evidence; no token inspection.
    def unique(pairs):
        result = {}
        for k, v in pairs:
            _require(k not in result)
            result[k] = v
        return result
    text = raw.decode('utf-8')
    starts = list(re.finditer(r'^\[[^\r\n]+ INFO Worker\] Job message:\r?\n', text, re.M))
    _require(len(starts) == 1)
    message, _ = json.JSONDecoder(object_pairs_hook=unique).raw_decode(text[starts[0].end():].lstrip())
    variables = message['variables']
    permissions = json.loads(variables['system.github.token.permissions']['value'], object_pairs_hook=unique)
    _require(permissions == PERMISSIONS)
    github = message['contextData']['github']
    _require(github['t'] == 2)
    context = unique((entry['k'], entry['v']) for entry in github['d'])
    expected = {'repository': REPO, 'repository_id': str(REPO_ID), 'ref': RUNTIME,
                'workflow_ref': WORKFLOW, 'sha': binding['runtime_sha'],
                'run_id': str(binding['run_id']), 'run_attempt': str(binding['run_attempt']),
                'event_name': 'workflow_dispatch'}
    for key, value in expected.items():
        _require(type(context[key]) is str and context[key] == value)
    _require(variables['system.github.job']['value'] == 'writer')
    job = message['jobId']
    _require(type(job) is str and re.fullmatch('[0-9a-f-]{36}', job))
    versions = re.findall(r'^\[[^\r\n]+ INFO Worker\] Version: ([0-9.]+)\r?$', text, re.M)
    commits = re.findall(r'^\[[^\r\n]+ INFO Worker\] Commit: ([0-9a-f]{40})\r?$', text, re.M)
    _require(len(versions) == len(commits) == 1)
    return dict(source=SOURCE, permissions=permissions, job='writer', worker_job_id=job,
                runner_version=versions[0], runner_commit=commits[0], context=expected,
                binding=binding)


def bind(writer):
    # The pinned workflow supplies this literal slot from github.token. Presence
    # and alias checks precede both permits. There is no replacement/fallback.
    token = os.environ.get('PROOF6_D03_JOB_TOKEN', '')
    _require(type(token) is str and bool(token) and all(33 <= ord(c) <= 126 for c in token)
             and token == os.environ.get('GH_TOKEN')
             and token != writer._installation_token)
    b = writer._journal.pending[writer._last_evidence['pending_record']]['binding']
    evidence = _permission_evidence(_worker_log(), b)
    validate(evidence, b)
    return token, evidence


def validate(evidence, binding):
    _require(set(evidence) == {'source', 'permissions', 'job', 'worker_job_id',
             'runner_version', 'runner_commit', 'context', 'binding'})
    _require(evidence['source'] == SOURCE and evidence['permissions'] == PERMISSIONS
             and evidence['job'] == 'writer' and _canonical(evidence['binding']) == _canonical(binding)
             and re.fullmatch('[0-9a-f-]{36}', evidence['worker_job_id'])
             and re.fullmatch('[0-9.]+', evidence['runner_version'])
             and re.fullmatch('[0-9a-f]{40}', evidence['runner_commit']))
    _require(evidence['context'] == {'repository': REPO, 'repository_id': str(REPO_ID),
        'ref': RUNTIME, 'workflow_ref': WORKFLOW, 'sha': binding['runtime_sha'],
        'run_id': str(binding['run_id']), 'run_attempt': str(binding['run_attempt']),
        'event_name': 'workflow_dispatch'})
