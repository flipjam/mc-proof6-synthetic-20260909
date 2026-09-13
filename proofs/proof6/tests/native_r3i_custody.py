"""Real fixed launch/exec + setup; synthetic permissions; all INET denied.

Exact partial source reproduces both review counterexamples. Corrected source
must reject each single forbidden slot before exec, IPC or qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import native_r3i_startup as prior
from r3i_custody_fixtures import BASE, CASES, environment, label

s = prior.s
SOURCE = Path(__file__).with_name('r3i-custody-evidence')/'partial-r3i-source'


class NativeCustody(unittest.TestCase):
    serial = 500
    setUp = prior.Startup.setUp
    tearDown = prior.Startup.tearDown
    reap = prior.Startup.reap
    start = prior.Startup.start
    producer = prior.Startup.producer

    def wrappers(self, old=False):
        loader = prior.prior.n.LOAD
        if old:
            loader = loader.replace(str(prior.prior.n.SOURCE), str(SOURCE/'d04_signal.py'))
            for name, expected in json.loads((SOURCE/'SHA256SUMS.json').read_bytes()).items():
                self.assertEqual(hashlib.sha256((SOURCE/name).read_bytes()).hexdigest(), expected)
        with patch.object(prior.prior.n, 'LOAD', loader):
            prior.Startup.wrappers(self)
        path = self.scripts/'d04_signal.py'
        code = path.read_text().replace("{'launch-writer':", "{'replay-startup':s.replay_startup,'launch-helper':lambda:s.launch('helper'),'launch-writer':")
        # A pre-exec negative cannot even import an authority/journal path.
        code = code.replace('import io', "import io\nclass DenyAuthorityImports:\n    def find_spec(self, fullname, *args):\n        if fullname in ('actions_runtime','writer','journal','outage','admission','reconcile'):\n            raise AssertionError('NO_AUTHORITY_PATH_IN_SETUP')\nsys.meta_path.insert(0,DenyAuthorityImports())")
        path.write_text(code)

    def complete_setup(self, extra=None, old=False):
        self.wrappers(old=old)
        self.assertTrue(self.start(extra), (self.root/'helper.log').read_text())
        rc, peer = self.producer(extra)
        self.assertEqual(rc, 0, peer.decode())
        rc, helper = self.reap()
        self.assertEqual(rc, 0, helper.decode())
        result = subprocess.run(['/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py','cleanup-setup'],
            cwd=self.temp, env=self.env, capture_output=True, timeout=12)
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        rows = [json.loads(line.split(b' ',1)[1]) for line in result.stdout.splitlines()
                if line.startswith(b'PROOF6_SIGNAL_SETUP_OUTPUT ')]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status_posts'], 0)
        self.assertTrue(rows[0]['helper_reaped'] and rows[0]['producer_reaped'])
        self.assertFalse(rows[0]['acceptance_credit'])
        raw = peer + helper + result.stdout + result.stderr
        for forbidden in (b'INERT_FORBIDDEN_VALUE', b'STATUS_SENTINEL', b'APP_SENTINEL',
                          b'STATUS_POST', b'"phase": "READY"', b'"phase": "END"'):
            self.assertNotIn(forbidden, raw)
        print(json.dumps(dict(case=next(iter(extra)) if extra else 'harmless_48_runner_variables',
            source=BASE if old else 'corrected_worktree', qualification='PASS',
            helper_reaped=True, producer_reaped=True, provider_writes=0,
            authority_journal_paths=False, D04_consumption=False, acceptance_credit=False)), flush=True)

    def test_old_GITHUB_TOKEN_full_setup_counterexample(self):
        self.complete_setup({'GITHUB_TOKEN': 'INERT_FORBIDDEN_VALUE'}, old=True)

    def test_old_unapproved_PROOF6_slot_full_setup_counterexample(self):
        self.complete_setup({'PROOF6_NEW_API_TOKEN': 'INERT_FORBIDDEN_VALUE'}, old=True)

    def test_corrected_harmless_dirty_environment_real_setup_pass(self):
        self.complete_setup()

    def test_prefilter_failure_survives_nonzero_cleanup_and_replay(self):
        self.negative('setup-helper', 'GITHUB_TOKEN', 'INERT_FORBIDDEN_VALUE')
        (self.root/'native.pid').write_text(str(self.procs[-1].pid))
        (self.root/'reaped.exit').write_text('1')
        command = ('set -e\nset +e\nresult=$(/usr/bin/python3 -I -B proofs/proof6/d04_signal.py cleanup-setup)\n'
                   'code=$?\nset -e\nprintf "%s\\n" "$result"\n'
                   'if test "$code" -ne 0; then /usr/bin/python3 -I -B proofs/proof6/d04_signal.py replay-startup; exit "$code"; fi\n')
        result = subprocess.run(['/bin/bash','-c',command], cwd=self.temp, env=self.env,
                                capture_output=True, timeout=12)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'HELPER_REAPED', result.stdout)
        self.assertIn(b'FORBIDDEN_CREDENTIAL_SLOT', result.stdout)
        self.assertNotIn(b'INERT_FORBIDDEN_VALUE', result.stdout + result.stderr)
        self.assertNotIn(b'PROOF6_SIGNAL_SETUP_OUTPUT', result.stdout)

    def negative(self, role, slot, value):
        self.wrappers()
        clean = environment(self.env, role) | prior.EXTRA
        self.assertNotIn(slot, clean)
        mode = {'helper':'launch-helper', 'setup-helper':'launch-setup',
                'setup-peer':'launch-peer', 'writer':'launch-writer'}[role]
        log = (self.root/'helper.log').open('wb'); self.files.append(log)
        proc = subprocess.Popen(['/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py',mode],
            cwd=self.temp, env=clean | {slot:value}, stdin=self.null, stdout=log, stderr=log, close_fds=True)
        self.procs.append(proc)
        self.assertEqual(proc.wait(timeout=8), 1)
        self.assertFalse(Path('/proc', str(proc.pid)).exists())
        raw = (self.root/'helper.log').read_bytes()
        records = [json.loads(line.split(b' ',1)[1]) for line in raw.splitlines()]
        self.assertEqual([r['stage'] for r in records],
                         ['LAUNCH_ENVIRONMENT','FORBIDDEN_CREDENTIAL_SLOT','FORBIDDEN_CREDENTIAL_SLOT'])
        self.assertEqual(records[-1]['kind'], 'BLOCKED')
        self.assertTrue(all(r['acceptance_credit'] is False for r in records))
        self.assertEqual({p.name for p in self.root.iterdir()}, {'helper.log'})
        for forbidden in (b'LAUNCH_EXEC', b'CUSTODY', b'IPC_READY', b'STATUS_POST', b'QUALIFIED',
                          b'INERT_FORBIDDEN_VALUE', b'APP_SENTINEL', b'STATUS_SENTINEL', slot.encode()):
            self.assertNotIn(forbidden, raw)


for role, slot, value in CASES:
    def test(self, role=role, slot=slot, value=value):
        self.negative(role, slot, value)
    setattr(NativeCustody, 'test_single_slot_' + label(role, slot, value), test)

if __name__ == '__main__':
    print(json.dumps(dict(kernel=os.uname().release, hosted_execution=False, acceptance_credit=False)), flush=True)
    unittest.main(verbosity=2)
