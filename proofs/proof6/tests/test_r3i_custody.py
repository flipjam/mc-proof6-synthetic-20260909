"""Pre-filter role custody: single-slot negatives and exact source continuity."""
import ast
import contextlib
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch
from r3i_custody_fixtures import BASE, CASES, TOKEN, environment, label

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'proofs/proof6'))
import d04_signal as s


class Custody(unittest.TestCase):
    def negative(self, role, slot, value):
        public = {k: 'PUBLIC' for k in s.PUBLIC_ENV} | {'PATH': '/usr/bin:/bin'}
        clean = environment(public, role)
        self.assertNotIn(slot, clean)  # Exactly one forbidden delivery.
        self.assertEqual(s.launch_environment(role, clean), clean)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.dict(os.environ, clean | {slot: value}, clear=True), \
                patch.object(s.os, 'execve') as execute, patch.object(s, 'binding') as binding, \
                patch.object(s, 'status_request') as provider, patch.object(socket, 'socket') as ipc:
            with self.assertRaises(ValueError):
                try:
                    s.launch(role)
                except ValueError as error:
                    s.startup_failure(error)
                    raise
        for call in (execute, binding, provider, ipc):
            call.assert_not_called()
        raw = output.getvalue()
        self.assertIn('FORBIDDEN_CREDENTIAL_SLOT', raw)
        self.assertNotIn('LAUNCH_EXEC', raw)
        for forbidden in ('INERT_FORBIDDEN_VALUE', 'STATUS_SENTINEL', 'APP_SENTINEL', slot):
            self.assertNotIn(forbidden, raw)

    def test_harmless_extras_filtered_for_every_role_without_suffix_heuristic(self):
        extra = {'DEBIAN_FRONTEND': 'nonsecret', 'ORDINARY_RUNNER_TOKEN': 'nonsecret'} | {
            'UNRELATED_%02d' % i: 'nonsecret' for i in range(47)}
        for role in ('helper', 'setup-helper', 'setup-peer', 'writer'):
            clean = environment({'PATH': '/usr/bin:/bin'}, role)
            self.assertEqual(s.launch_environment(role, clean | extra), clean)

    def test_reserved_namespace_has_no_credential_suffix_escape(self):
        for role in ('helper', 'setup-helper', 'setup-peer', 'writer'):
            for slot in ('PROOF6_NEW_PASSWORD', 'PROOF6_NEW_API_KEY', 'PROOF6_NEW_SECRET', 'PROOF6_APPUNAPPROVED'):
                with self.subTest(role=role, slot=slot):
                    self.negative(role, slot, '')

    def test_all_explicit_writer_inputs_remain_allowed(self):
        clean = {k: 'INERT_ALLOWED' for k in s.PUBLIC_ENV | s.SYSTEM_ENV | s.WRITER_ENV}
        self.assertEqual(s.launch_environment('writer', clean), clean)

    def test_helper_requires_its_nonempty_dedicated_slot(self):
        for role in ('helper', 'setup-helper'):
            for clean in ({}, {TOKEN: ''}):
                with self.assertRaises(ValueError):
                    s.launch_environment(role, clean)

    def test_counterexample_fixture_is_exact_partial_source(self):
        folder = Path(__file__).with_name('r3i-custody-evidence')/'partial-r3i-source'
        for name in ('d04_signal.py', 'd04_capability.py'):
            self.assertEqual((folder/name).read_bytes(), subprocess.check_output([
                'git', '-C', str(ROOT), 'show', BASE+':proofs/proof6/'+name]))

    def test_signal_AST_only_launch_check_and_fixed_stage_change(self):
        old = ast.parse(subprocess.check_output(['git', '-C', str(ROOT), 'show', BASE+':proofs/proof6/d04_signal.py']))
        new = ast.parse((ROOT/'proofs/proof6/d04_signal.py').read_bytes())
        def remainder(tree):
            return [ast.dump(n) for n in tree.body if not (
                isinstance(n, ast.FunctionDef) and n.name == 'launch_environment' or
                isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'STARTUP_STAGES')]
        self.assertEqual(remainder(old), remainder(new))
        prior = next(n for n in old.body if isinstance(n, ast.Assign) and n.targets[0].id == 'STARTUP_STAGES')
        self.assertEqual(s.STARTUP_STAGES, ast.literal_eval(prior.value) | {'FORBIDDEN_CREDENTIAL_SLOT'})

    def test_all_other_production_workflow_plan_and_prior_tests_byte_identical(self):
        paths = subprocess.check_output(['git', '-C', str(ROOT), 'ls-tree', '-r', '--name-only', BASE]).decode().splitlines()
        for path in paths:
            if (path.startswith('proofs/proof6/') or path.startswith('.github/workflows/')) and path not in (
                    'proofs/proof6/d04_signal.py', 'proofs/proof6/build.json'):
                self.assertEqual((ROOT/path).read_bytes(), subprocess.check_output(['git', '-C', str(ROOT), 'show', BASE+':'+path]), path)
        plan = (ROOT/'proofs/proof6/proof_plan.json').read_bytes()
        self.assertEqual(hashlib.sha256(plan).hexdigest(), '81926d6ce00e3b36f84404b217b29c22e4224b2f002115382614feb1a42c3617')


for role, slot, value in CASES:
    def test(self, role=role, slot=slot, value=value):
        self.negative(role, slot, value)
    setattr(Custody, 'test_single_slot_' + label(role, slot, value), test)

if __name__ == '__main__':
    unittest.main(verbosity=2)
