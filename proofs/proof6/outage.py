"""Fixed 120-second isolated-worker connectivity outage; never a writer fault mode."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

DURATION = 120
ROOT = Path(__file__).resolve().parents[2]

def isolated():
    # A new network namespace has only an unconfigured loopback interface and
    # no route out. Prove the absence of network devices/routes, not just DNS loss.
    devices = sorted(name for _, name in socket.if_nameindex())
    if devices != ['lo']:
        raise ValueError('ISOLATION_NOT_ESTABLISHED')
    routes = Path('/proc/net/route').read_text().splitlines()
    if len(routes) != 1:
        raise ValueError('ISOLATION_NOT_ESTABLISHED')
    try:
        socket.create_connection(('api.github.com', 443), timeout=3).close()
    except OSError:
        return {'devices': devices, 'ipv4_routes': 0,
                'api_github_connection': 'unavailable'}
    raise ValueError('API_CONNECTIVITY_STILL_AVAILABLE')

def worker():
    # No token or caller input enters this child. It occupies the sole serialized
    # mutation job, cannot write authority, and its namespace dies with the process.
    emit = lambda phase, **data: print(json.dumps(dict(phase=phase, observed_at_unix=time.time(), **data), sort_keys=True), flush=True)
    first = isolated()
    start = time.monotonic()
    emit('READY', duration_seconds=DURATION, observation=first)
    while time.monotonic() - start < DURATION:
        time.sleep(max(0, min(1, DURATION - (time.monotonic() - start))))
    emit('END', elapsed_seconds=time.monotonic() - start, observation=isolated())

def outage(emit):
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
    emit({'phase': 'START', 'duration_seconds': DURATION, 'target': 'api.github.com'})
    # Fixed executable/namespace/child: no caller-selected network controls.
    with subprocess.Popen(['/usr/bin/sudo', '-n', '/usr/bin/timeout', '--signal=KILL', '135',
                           '/usr/bin/unshare', '--net', '/usr/bin/python3', '-B',
                           str(Path(__file__).resolve()), '--isolated-worker'],
                          env=env, cwd=ROOT, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True) as child:
        observations = []
        for line in child.stdout:
            item = json.loads(line)
            observations.append(item)
            emit(item)  # READY is visible while the isolated worker holds the lock.
        code = child.wait(timeout=10)
    if code != 0 or [x['phase'] for x in observations] != ['READY', 'END']:
        raise ValueError('OUTAGE_NOT_ESTABLISHED')
    # Child teardown restores normal worker availability without persistent
    # host firewall/interface changes. Caller connectivity is independent evidence.
    return {'result': 'OUTAGE_COMPLETED', 'duration_seconds': DURATION,
            'update_attempted': False, 'remote_outcome': 'not_attempted',
            'old_sha': None, 'candidate_commit': None, 'new_sha': None}

if __name__ == '__main__':
    if sys.argv[1:] != ['--isolated-worker']:
        raise SystemExit(2)
    worker()
