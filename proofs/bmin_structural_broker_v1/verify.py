"""Offline verification, including unchanged canonical Proof-1/2 test suites.

Usage: python -B proofs/bmin_structural_broker_v1/verify.py --architecture-repo PATH
Only local Git object reads and local scratch Git are permitted. No fetch/push.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

AREA = Path(__file__).resolve().parent
ROOT = AREA.parents[1]
AUTHORITY = '6ba4056b4714e7481636a93cee8d4690b6d8f521'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--architecture-repo', required=True)
    args = parser.parse_args()
    results = []
    with tempfile.TemporaryDirectory(prefix='bmin-offline-') as tmp:
        scratch = Path(tmp)
        guard = scratch / 'guard'
        guard.mkdir()
        (guard / 'sitecustomize.py').write_text(
            "import sys\ndef audit(event,args):\n"
            "    if event.startswith(('socket.connect','socket.bind','socket.getaddrinfo')):\n"
            "        raise AssertionError('OFFLINE_NETWORK_FORBIDDEN')\n"
            "sys.addaudithook(audit)\n", encoding='ascii')
        env = dict(os.environ, PYTHONPATH=str(guard), PYTHONDONTWRITEBYTECODE='1',
                   GIT_ALLOW_PROTOCOL='file', GIT_TERMINAL_PROMPT='0',
                   GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        # Baseline test files are read byte-for-byte from the required read-only
        # architectural authority; executable components are the synthetic base.
        for folder, names in [('proof1', ['test_replay.py', 'test_adversarial.py']),
                              ('proof2', ['test_gate.py'])]:
            destination = scratch / 'proofs' / folder
            destination.mkdir(parents=True)
            program = 'replay.py' if folder == 'proof1' else 'gate.py'
            (destination / program).write_bytes((ROOT / 'proofs' / folder / program).read_bytes())
            for name in names:
                raw = subprocess.check_output(['git', '-C', args.architecture_repo, 'show',
                    AUTHORITY + ':proofs/' + folder + '/' + name], env=env)
                (destination / name).write_bytes(raw)
        suites = [('focused', AREA / 'tests'), ('proof1_baseline', scratch / 'proofs/proof1'),
                  ('proof2_baseline', scratch / 'proofs/proof2')]
        for name, directory in suites:
            run = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover', '-s', str(directory), '-v'],
                                 env=env, capture_output=True, text=True, timeout=180)
            output = run.stdout + run.stderr
            count = re.search(r'Ran (\d+) tests?', output)
            item = dict(suite=name, count=int(count[1]) if count else 0, exit_code=run.returncode,
                        result='PASS' if run.returncode == 0 and count else 'FAIL', output=output)
            results.append(item)
            print(f'{name}: {item["count"]} tests, {item["result"]}', flush=True)
    sys.path.insert(0, str(AREA))
    from core import source_hashes
    report = dict(schema='BMIN_OFFLINE_VERIFICATION_V1', utc=datetime.now(timezone.utc).isoformat(),
        python=sys.version, synthetic_base='6313eb40da86a179a48a87a5a28c6bc7217e4b6f',
        architecture_authority=AUTHORITY, network_used=False,
        network_guard='Python audit hooks; socket mocks; local Git GIT_ALLOW_PROTOCOL=file',
        source_hashes=source_hashes(), suites=results, live_credential_custody_proven=False)
    (AREA / 'verification.json').write_bytes((json.dumps(report, indent=2) + '\n').encode('ascii'))
    return 0 if all(r['result'] == 'PASS' for r in results) else 1


if __name__ == '__main__': raise SystemExit(main())
