"""Canonical caller type counterexamples through production replay and admission.

SEND_ARMED and TERMINAL bind their caller through the exact PENDING record;
they have no independent caller field. Fixtures rebuild that complete ancestry.
Only inert provider objects are changed. No live permission claim is made.
"""
import contextlib
import copy
import io
import socket
import unittest
from unittest.mock import patch

from test_r3f import Fixture, e, j, w


class CallerTypes(Fixture):
    def history(self, stage, field, value):
        journal, pending, candidate = self.begin()
        row = copy.deepcopy(self.g.row(pending))
        row['binding']['caller'][field] = value
        pending, _ = self.g.record(row, self.g.genesis)
        head = pending
        if stage != 'PENDING':
            head, _ = self.g.record(dict(schema=j.SCHEMA, type='SEND_ARMED',
                                         pending=pending), head)
            # Affirmative candidate evidence would permit missing completion.
            self.g.refs[w.REF] = candidate
        if stage == 'TERMINAL':
            head, _ = self.g.record(self.terminal(pending, candidate), head)
        self.g.refs[j.REF] = head
        return candidate

    def reject(self, stage, field, value):
        self.history(stage, field, value)
        before = (self.g.journal_sends, self.g.authority_sends, dict(self.g.refs))
        with self.assertRaises(ValueError):
            self.recovery()
        # Fresh construction replays the entire canonical chain before recover.
        with self.assertRaises(ValueError):
            self.recovery().recover(self.current)
        obj = e.writer(self.g, 71)
        with self.assertRaises(ValueError):
            obj.recover_only()
        self.assertEqual(obj._last_evidence['admission'], 'BLOCKED')
        self.assertFalse(obj._last_evidence['update_attempted'])
        # A later valid proposal must not reach even the fresh admission gate.
        proposal = w._canonical(e.PLAN['faults']['D07_DROP_PATCH_RESPONSE']['proposal'])
        _, result = self.call(proposal, n=72)
        self.assertFalse(result['update_attempted'])
        self.assertNotIn('gate', result)
        self.assertNotEqual(result['result'], 'COMMITTED')
        self.assertEqual(before, (self.g.journal_sends, self.g.authority_sends, self.g.refs))

    def test_pending_admin_zero(self): self.reject('PENDING', 'admin', 0)
    def test_pending_maintain_zero(self): self.reject('PENDING', 'maintain', 0)
    def test_armed_admin_zero(self): self.reject('SEND_ARMED', 'admin', 0)
    def test_armed_maintain_zero(self): self.reject('SEND_ARMED', 'maintain', 0)
    def test_terminal_admin_zero(self): self.reject('TERMINAL', 'admin', 0)
    def test_terminal_maintain_zero(self): self.reject('TERMINAL', 'maintain', 0)

    def other_type(self, value):
        # Exercise both completion and read-only recovery with each independent
        # substitution; the other caller flag always remains actual False.
        for stage in ('SEND_ARMED', 'TERMINAL'):
            for field in ('admin', 'maintain'):
                with self.subTest(stage=stage, field=field):
                    self.setUp()
                    self.reject(stage, field, value)

    def test_float_zero(self): self.other_type(0.0)
    def test_string_false(self): self.other_type('false')
    def test_string_zero(self): self.other_type('0')
    def test_null(self): self.other_type(None)
    def test_boolean_true(self): self.other_type(True)

    def positive(self, field):
        for stage in ('SEND_ARMED', 'TERMINAL'):
            with self.subTest(stage=stage):
                self.setUp()
                candidate = self.history(stage, field, False)
                before = self.g.journal_sends
                with contextlib.redirect_stdout(io.StringIO()):
                    result = e.writer(self.g, 71).recover_only()
                self.assertEqual(result['admission'], 'CONFIRMED')
                self.assertEqual(result['authority_sha'], candidate)
                self.assertEqual(self.g.journal_sends - before, int(stage == 'SEND_ARMED'))
                self.assertEqual(self.g.authority_sends, 0)
                # Confirm a second recovery is read-only after either path.
                before = self.g.journal_sends
                self.recovery().recover(self.current)
                self.assertEqual(before, self.g.journal_sends)
                proposal = w._canonical(e.PLAN['faults']['D07_DROP_PATCH_RESPONSE']['proposal'])
                self.assertEqual(self.call(proposal, n=72)[1]['result'], 'COMMITTED')
                self.assertEqual(self.g.authority_sends, 1)

    def test_actual_false_admin(self): self.positive('admin')
    def test_actual_false_maintain(self): self.positive('maintain')

    def test_caller_id_type(self):
        # A float equal to the fixed integer is already rejected by parse;
        # bool cannot equal this fixed ID. The binding now checks int directly.
        for value in (float(e.CALLER['id']), True, str(e.CALLER['id']), None):
            with self.subTest(value=value):
                self.setUp()
                self.reject('TERMINAL', 'id', value)
        self.setUp()
        journal = self.recovery()
        for value in (float(e.CALLER['id']), True):
            binding = journal.operation_binding(self.proposal, '')
            binding['caller'] = dict(binding['caller'], id=value)
            with self.subTest(direct_id=value), self.assertRaises(ValueError):
                journal.check_binding(binding)


if __name__ == '__main__':
    with patch.object(socket, 'socket', side_effect=AssertionError('OFFLINE_ONLY')):
        unittest.main(verbosity=2)
