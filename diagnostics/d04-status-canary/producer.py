"""Credential-free fixed producer. NON-ACCEPTANCE; no isolation or authority work."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

WINDOW_SECONDS = 20
ENV_KEYS = {'PATH', 'LANG', 'CANARY_RUN_ID', 'CANARY_ATTEMPT', 'CANARY_SHA'}

def main():
    assert set(os.environ) == ENV_KEYS
    assert os.environ['PATH'] == '/usr/bin:/bin' and os.environ['LANG'] == 'C.UTF-8'
    assert re.fullmatch(r'[1-9][0-9]*', os.environ['CANARY_RUN_ID'])
    assert os.environ['CANARY_ATTEMPT'] == '1'
    assert re.fullmatch(r'[0-9a-f]{40}', os.environ['CANARY_SHA'])
    root = Path(__file__).resolve().parent
    assert sys.argv == [str(root / 'producer.py')] and Path.cwd() == root
    assert set(p.name for p in root.iterdir()) == {'producer.py', 'helper.py'}
    fds = {}
    for p in Path('/proc/self/fd').iterdir():
        try:
            fds[p.name] = os.readlink(p)
        except FileNotFoundError:
            pass
    assert set(fds) == {'0', '1', '2'}
    assert all(re.fullmatch(r'pipe:\[[0-9]+\]', fds[x]) for x in ('0', '1'))
    assert fds['2'] == '/dev/null'
    custody = {'environment_keys': sorted(os.environ), 'argv': sys.argv,
               'descriptors': fds, 'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                           for p in root.iterdir()},
               'no_credential_delivery': True, 'credential_discovery_implemented': False}
    assert sys.stdin.buffer.readline(4) == b'GO\n'
    binding = {'schema': 'PROOF6_STATUS_CANARY_V1', 'run_id': int(os.environ['CANARY_RUN_ID']),
               'attempt': 1, 'sha': os.environ['CANARY_SHA'], 'pid': os.getpid(), 'custody': custody}
    start = time.monotonic()
    for phase in ('READY', 'END'):
        if phase == 'END':
            while time.monotonic() - start < WINDOW_SECONDS:
                time.sleep(max(0, min(0.25, WINDOW_SECONDS - (time.monotonic() - start))))
        now = time.monotonic()
        if phase == 'READY':
            start = now
        event = dict(binding, phase=phase, utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     monotonic=now)
        print(json.dumps(event, sort_keys=True, separators=(',', ':')), flush=True)

if __name__ == '__main__':
    main()
