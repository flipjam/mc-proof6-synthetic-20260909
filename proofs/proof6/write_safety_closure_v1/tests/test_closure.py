import ast
import contextlib
import copy
import inspect
import io
import json
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch
from fixtures import *
from fixtures import _canonical, _digest
import collector
import d03_rejection


class Closure(unittest.TestCase):
    def setUp(self):
        self.sockets = patch.object(socket, 'socket', side_effect=AssertionError('OFFLINE_ONLY'))
        self.sockets.start()
        self.addCleanup(self.sockets.stop)

    def complete(self):
        g, m, q0, results = campaign()
        e = evidence(g, m, q0, results)
        return g, m, e

    def collect(self, g, m, e):
        return collector.collect(m, e, lambda suffix: g.api('offline-token', 'GET', j.BASE+suffix))

    def test_full_path_exact_budgets(self):
        g, m, q0, results = campaign()
        self.assertEqual([r['result'] for r in results], ['INDETERMINATE', 'INDETERMINATE', 'COMMITTED'])
        self.assertEqual((g.authority_sends, g.journal_sends), (3, 12))
        journal = j.Journal(writer(g, m))
        self.assertEqual(len(journal.rows), 11)
        self.assertEqual(journal.used, set(pc.FAULTS))
        self.assertEqual(len(journal.terminals), 3)

    def test_collector_known_good(self):
        g, m, e = self.complete()
        result = self.collect(g, m, e)
        self.assertEqual(result['result'], 'PASS', result)

    def test_collector_nine_required_falsifications(self):
        g, m, e = self.complete()
        journal = j.Journal(writer(g, m))
        d03, d07, normal = list(journal.pending)
        terminal = journal.terminals[d03][0]
        mutations = {
            'missing_decisive_d03': lambda gg, mm, ee: gg.objects.pop(gg.objects[terminal]['tree']['sha']),
            'missing_journal_record': lambda gg, mm, ee: gg.objects.pop(d07),
            'stale_authority': lambda gg, mm, ee: gg.refs.update({REF: mm['baseline_commit']}),
            'wrong_operation_terminal': lambda gg, mm, ee: ee['sibling'].update(winner=journal.terminals[normal][0]),
            'wrong_sibling': lambda gg, mm, ee: ee['sibling'].update(loser=ee['sibling']['winner']),
            'arbitrary_descendant': lambda gg, mm, ee: gg.refs.update({REF: gg.commit(gg.objects[gg.refs[REF]]['tree']['sha'], [gg.refs[REF]], 'arbitrary')}),
            'missing_process': lambda gg, mm, ee: ee.pop('raw_process'),
            'missing_identity': lambda gg, mm, ee: mm.pop('source_tree'),
            'writer_pass_contradiction': lambda gg, mm, ee: ee['authority_attempts'].append(copy.deepcopy(ee['authority_attempts'][0])),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                gg, mm, ee = copy.deepcopy(g), copy.deepcopy(m), copy.deepcopy(e)
                # api closure belongs to the original Git; use object GET lookup independently.
                mutate(gg, mm, ee)
                def get(suffix):
                    if suffix.startswith('/git/ref/'):
                        ref = 'refs/' + suffix.removeprefix('/git/ref/')
                        return {'ref': ref, 'object': {'type': 'commit', 'sha': gg.refs[ref]}}
                    if suffix.startswith(('/git/commits/', '/git/trees/', '/git/blobs/')):
                        return copy.deepcopy(gg.objects[suffix.rsplit('/', 1)[1]])
                    return g.api('offline-token', 'GET', j.BASE+suffix)
                self.assertNotEqual(collector.collect(mm, ee, get)['result'], 'PASS')

    def test_reinvocation_and_unknown_never_mutate(self):
        g, m, q0, results = campaign()
        for op in (*pc.FAULTS, '', 'UNKNOWN', 'P6WSV1-D03-01'):
            before = (len(g.calls), g.authority_sends, g.journal_sends)
            obj = writer(g, m, op, 61)
            with contextlib.redirect_stdout(io.StringIO()):
                result = obj.commit_transition(_canonical(m['proposals'].get(op, m['proposals'][''])), op)
            self.assertFalse(result['update_attempted'])
            self.assertEqual((g.authority_sends, g.journal_sends), before[1:])
            self.assertFalse(any(c[0] != 'GET' for c in g.calls[before[0]:]))

    def test_d03_canonical_recovery_zero_patches(self):
        g, m, _ = setup()
        obj, result = execute(g, m, pc.FAULTS[0])
        self.assertEqual(result['result'], 'INDETERMINATE')
        self.assertEqual(obj._journal_confirmation['reason'], 'D03_CONFIRMATION_LOST')
        before = (g.authority_sends, g.journal_sends)
        with contextlib.redirect_stdout(io.StringIO()):
            writer(g, m, run=51).recover_only()
        self.assertEqual((g.authority_sends, g.journal_sends), before)

    def test_stale_authority_cannot_recover(self):
        g, m, _ = setup()
        execute(g, m, pc.FAULTS[0])
        execute(g, m, pc.FAULTS[1], 52)
        g.refs[REF] = m['baseline_commit']
        before = (g.authority_sends, g.journal_sends)
        with self.assertRaises(ValueError):
            writer(g, m, run=53).recover_only()
        self.assertEqual((g.authority_sends, g.journal_sends), before)

    def test_gate_replay_and_stale_reject(self):
        g, m, q0, results = campaign()
        history = g.row(g.refs[REF])
        for p in m['proposals'].values():
            self.assertEqual(q.gate().decide(history, p)['decision'], 'REJECT')
        obj = writer(g, m, pc.FAULTS[0])
        p = copy.deepcopy(m['proposals'][pc.FAULTS[0]])
        p['expected_state_sha256'] = '0'*64
        before = g.journal_sends
        result = obj.commit_transition(_canonical(p), pc.FAULTS[0])
        self.assertFalse(result['update_attempted'])
        self.assertEqual(g.journal_sends, before)

    def test_unknown_case_and_forbidden_selectors(self):
        g, m, _ = setup()
        for key in ('repository', 'ref', 'journal_ref', 'runtime_ref', 'credential', 'parent_sha',
                    'candidate', 'force', 'endpoint', 'disposition', 'recovery_target', 'authorization'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                pc.request({'case': 'RECOVER', key: 'injected'}, m)
        for case in ('UNKNOWN', 'D02_PRE_SEND_STOP', 'D04_CONNECTIVITY_OUTAGE', True, None):
            with self.assertRaises(ValueError):
                pc.request({'case': case}, m)
        obj = writer(g, m)
        for kwargs in ({'candidate': 'e'*40}, {'disposition': 'COMMITTED'}, {'operation': pc.FAULTS[0]}):
            with self.assertRaises(TypeError):
                obj.recover_only(**kwargs)

    def test_manifest_and_q0_substitution(self):
        g, m, q0 = setup()
        for field in ('source_commit', 'source_tree', 'build_sha256', 'proof_plan_sha256'):
            changed = copy.deepcopy(m)
            changed[field] = '0'*len(changed[field])
            with self.subTest(field=field), self.assertRaises(ValueError):
                q.qualify_q0(changed, q0)
        for field, value in (('admin', True), ('maintain', True), ('role', 'admin'), ('credential_source', 'privileged')):
            changed = copy.deepcopy(q0)
            changed['ordinary'][field] = value
            mm = copy.deepcopy(m); mm['q0_evidence_sha256'] = _digest(_canonical(changed))
            with self.subTest(field=field), self.assertRaises(ValueError):
                q.qualify_q0(mm, changed)
        for source in ('arbitrary-token', 'official-installation-action/environment-secret'):
            mm = copy.deepcopy(m); mm['custody']['d03_credential_source'] = source
            with self.assertRaises(ValueError):
                q.validate_manifest(mm)

    def test_exact_d03_classifier_framing_and_second_send(self):
        for body in (b'{"message":"Forbidden"}', b'{"message":"rate limit"}',
                     b'{"message":"Resource not accessible by integration","status":"401"}'):
            with self.assertRaises(ValueError):
                d03_rejection.body(body)
        g, m, _ = setup()
        obj, result = execute(g, m, pc.FAULTS[0])
        self.assertIsNone(obj._transport_candidate)
        with self.assertRaises(ValueError), patch.object(w.http.client, 'HTTPSConnection', side_effect=AssertionError('SECOND_SEND')):
            obj._patch(result['candidate_commit'], False, result)
        self.assertEqual(g.authority_sends, 1)

    def test_wrong_terminal_and_loser_replacement(self):
        g, m, e = self.complete()
        journal = j.Journal(writer(g, m))
        rows = copy.deepcopy(journal.rows)
        rows[7][1]['pending'] = rows[1][0]
        with self.assertRaises(ValueError):
            journal.validate(rows)
        with self.assertRaises(Exception):
            g.advance(JOURNAL_REF, e['sibling']['loser'])
        self.assertEqual(g.refs[JOURNAL_REF], journal.head)

    def test_recovery_has_no_send_path(self):
        for function in (w._Writer.recover_only, j.Journal.recover, j.Journal.reconcile):
            source = inspect.getsource(function)
            for forbidden in ('._patch(', '.arm(', '.take_send(', '_transport_candidate ='):
                self.assertNotIn(forbidden, source)
        g, m, _ = setup()
        execute(g, m, pc.FAULTS[0])
        execute(g, m, pc.FAULTS[1], 52)
        with patch.object(w._Writer, '_patch', side_effect=AssertionError('RECOVERY_AUTHORITY_SEND')), \
             patch.object(j.Journal, 'arm', side_effect=AssertionError('RECOVERY_ARM')), \
             contextlib.redirect_stdout(io.StringIO()):
            result = writer(g, m, run=53).recover_only()
        self.assertEqual(result['result'], 'RECOVERY_CONFIRMED')

    def test_d07_drops_after_transmission_and_cannot_resend(self):
        g, m, _ = setup()
        execute(g, m, pc.FAULTS[0])
        g.received = False
        obj, result = execute(g, m, pc.FAULTS[1], 52)
        self.assertTrue(result['request_transmission_completed'])
        self.assertTrue(result['response_path_discarded'])
        self.assertFalse(g.received)
        self.assertFalse(result['response_consumed'])
        with patch.object(w.http.client, 'HTTPSConnection', side_effect=AssertionError('SECOND_SEND')), self.assertRaises(ValueError):
            obj._patch(result['candidate_commit'], True, result)
        self.assertEqual(g.authority_sends, 2)

    def test_arbitrary_descendant_blocks_recovery(self):
        g, m, _ = setup()
        execute(g, m, pc.FAULTS[0])
        execute(g, m, pc.FAULTS[1], 52)
        head = g.refs[REF]
        g.refs[REF] = g.commit(g.objects[head]['tree']['sha'], [head], 'unexplained descendant')
        before = (g.authority_sends, g.journal_sends)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
            writer(g, m, run=53).recover_only()
        self.assertEqual((g.authority_sends, g.journal_sends), before)

    def test_d03_reinvocation_immediately_after_loss(self):
        g, m, _ = setup()
        execute(g, m, pc.FAULTS[0])
        before = (g.authority_sends, g.journal_sends)
        obj, result = execute(g, m, pc.FAULTS[0], 51)
        self.assertFalse(result['update_attempted'])
        self.assertEqual((g.authority_sends, g.journal_sends), before)

    def test_normal_cannot_start_while_d07_unresolved(self):
        g, m, _ = setup()
        execute(g, m, pc.FAULTS[0])
        execute(g, m, pc.FAULTS[1], 52)
        before = (g.authority_sends, g.journal_sends)
        obj, result = execute(g, m, '', 53)
        self.assertFalse(result['update_attempted'])
        self.assertEqual((g.authority_sends, g.journal_sends), before)

    def test_q0_consumes_nothing_and_rejects_mutation(self):
        g, m, q0 = setup()
        self.assertEqual(q.qualify_q0(m, q0)['consumptions'], 0)
        self.assertEqual((g.authority_sends, g.journal_sends), (0, 0))
        bad = copy.deepcopy(q0); bad['consumptions'] = 1
        m['q0_evidence_sha256'] = _digest(_canonical(bad))
        with self.assertRaises(ValueError):
            q.qualify_q0(m, bad)

    def test_native_unprovisioned_launcher_blocks(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(AREA/'launcher.py')],
            env={}, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 2)
        self.assertIn('BLOCKED', result.stdout)
        self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
