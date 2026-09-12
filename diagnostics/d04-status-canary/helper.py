"""Fixed diagnostic-only commit-status helper. No proof runtime imports."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time
import urllib.request

REPO = 'flipjam/mc-proof6-synthetic-20260909'
BRANCH = 'refs/heads/codex/proof6-r3h-live-status-canary-20260912-01'
KEYS = {'schema', 'run_id', 'attempt', 'sha', 'pid', 'custody', 'phase', 'utc', 'monotonic'}

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def emit(kind, **fields):
    print('PROOF6_STATUS_CANARY ' + json.dumps(dict(kind=kind, utc=utc(), **fields), sort_keys=True), flush=True)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('REDIRECT_FORBIDDEN')

def post(token, sha, run_id, attempt, event):
    context = f'proof6/d04-signal-canary/{run_id}/{attempt}/{sha}'
    payload = {'state': 'pending' if event['phase'] == 'READY' else 'success', 'context': context,
               'description': f"{event['phase']} r={run_id} a={attempt} sha={sha} p={event['pid']}",
               'target_url': f'https://github.com/{REPO}/actions/runs/{run_id}'}
    assert len(context) <= 100 and len(payload['description']) <= 140
    request = urllib.request.Request(f'https://api.github.com/repos/{REPO}/statuses/{sha}',
        data=json.dumps(payload, sort_keys=True).encode(), method='POST', headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'proof6-fixed-status-canary'})
    started = utc()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=5) as response:
        assert response.status == 201
        raw = response.read(65537)
        assert len(raw) <= 65536
        item = json.loads(raw)
        assert all(item[k] == payload[k] for k in payload)
        assert item['creator']['login'] == 'github-actions[bot]'
        receipt = {'started_at': started, 'completed_at': utc(), 'http_status': response.status,
                   'headers': {k: response.headers.get(k) for k in ('Date', 'X-GitHub-Request-Id',
                              'X-Accepted-GitHub-Permissions')}, 'payload': payload, 'response': item}
    emit('STATUS_POST', phase=event['phase'], receipt=receipt)

def timeout(*_):
    raise TimeoutError('CANARY_DEADLINE')

def main():
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(60)
    assert os.environ['GITHUB_REPOSITORY'] == REPO
    assert os.environ['GITHUB_REPOSITORY_ID'] == '1363510385'
    assert os.environ['GITHUB_REF'] == BRANCH and os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch'
    assert os.environ['GITHUB_WORKFLOW_REF'] == REPO + '/.github/workflows/proof6-writer.yml@' + BRANCH
    assert os.environ['GITHUB_RUN_ATTEMPT'] == '1'
    assert not any(k.startswith('PROOF6_APP') or k == 'PROOF6_FROZEN_MANIFEST' for k in os.environ)
    run_id = int(os.environ['GITHUB_RUN_ID']); attempt = 1; sha = os.environ['GITHUB_SHA']
    assert run_id > 0 and re.fullmatch(r'[0-9a-f]{40}', sha)
    token = os.environ.pop('CANARY_STATUS_TOKEN')
    assert token and token not in '\0'.join(sys.argv)
    root = Path(__file__).resolve().parent
    assert set(p.name for p in root.iterdir()) == {'producer.py', 'helper.py'}
    sources = {p.name: p.read_bytes() for p in root.iterdir()}
    assert all(token.encode() not in raw for raw in sources.values())
    child_env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'CANARY_RUN_ID': str(run_id),
                 'CANARY_ATTEMPT': '1', 'CANARY_SHA': sha}
    command = ['/usr/bin/python3', '-I', '-B', str(root / 'producer.py')]
    child = subprocess.Popen(command, cwd=root, env=child_env, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True, bufsize=0)
    try:
        # Inspect only this implementation-created child's nonsecret delivery path.
        deadline = time.monotonic() + 3
        while True:
            argv = Path(f'/proc/{child.pid}/cmdline').read_bytes().split(b'\0')[:-1]
            if argv == [x.encode() for x in command]:
                break
            assert child.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)
        delivered = Path(f'/proc/{child.pid}/environ').read_bytes()
        assert token.encode() not in delivered
        actual_env = dict(x.split(b'=', 1) for x in delivered.split(b'\0') if x)
        assert actual_env == {k.encode(): v.encode() for k, v in child_env.items()}
        expected_fds = {'0': f'pipe:[{os.fstat(child.stdin.fileno()).st_ino}]',
                        '1': f'pipe:[{os.fstat(child.stdout.fileno()).st_ino}]', '2': '/dev/null'}
        while True:
            actual_fds = {}
            for p in Path(f'/proc/{child.pid}/fd').iterdir():
                try:
                    actual_fds[p.name] = os.readlink(p)
                except FileNotFoundError:
                    pass
            if actual_fds == expected_fds:
                break
            assert child.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)
        emit('HELPER_CUSTODY_READY', helper_pid=os.getpid(), producer_pid=child.pid,
             producer_environment_keys=sorted(child_env), producer_argv=command,
             producer_descriptors=actual_fds, source_sha256={k:hashlib.sha256(v).hexdigest() for k,v in sources.items()},
             no_credential_file=True, no_app_credential=True, no_credential_delivery=True,
             no_hostile_root_secrecy_claim=True)
        child.stdin.write(b'GO\n'); child.stdin.close()
        previous = None
        for phase in ('READY', 'END'):
            assert select.select([child.stdout], [], [], 25)[0]
            raw = child.stdout.readline(16385)
            assert raw.endswith(b'\n') and len(raw) <= 16384 and token.encode() not in raw
            event = json.loads(raw)
            assert set(event) == KEYS
            assert event['schema'] == 'PROOF6_STATUS_CANARY_V1' and event['phase'] == phase
            assert event['run_id'] == run_id and event['attempt'] == attempt and event['sha'] == sha
            assert event['pid'] == child.pid and event['custody']['no_credential_delivery'] is True
            assert set(event['custody']['environment_keys']) == set(child_env)
            assert event['custody']['descriptors'] == expected_fds
            assert event['custody']['files'] == {k:hashlib.sha256(v).hexdigest() for k,v in sources.items()}
            if previous is not None:
                assert event['monotonic'] - previous['monotonic'] >= 20
            emit('LOCAL_EVENT', event=event)
            post(token, sha, run_id, attempt, event)
            previous = event
        assert child.wait(timeout=3) == 0 and child.stdout.read(1) == b''
        emit('PRODUCER_REAPED', producer_pid=child.pid, returncode=child.returncode)
        # Fixed observation margin for external END detection before job completion.
        time.sleep(10)
        emit('COMPLETED', acceptance_credit=False)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        signal.alarm(0)

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        emit('FAILED', exception_type=type(exc).__name__, acceptance_credit=False)
        raise SystemExit(1)
