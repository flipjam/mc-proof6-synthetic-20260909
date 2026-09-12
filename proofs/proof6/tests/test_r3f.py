"""Production validators and transports with inert provider/clock fixtures.
No GitHub permission, force=false enforcement or network-isolation claim.
"""
import ast
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import Mock, patch
import urllib.error

from support import legacy as e, ROOT, begin_valid
import app_probes
import sibling_canary

w, j, pc, ar = e.w, e.j, e.pc, e.ar


class Fixture(unittest.TestCase):
    def setUp(self):
        self.g = e.Git()
        self.w = e.writer(self.g)
        self.proposal = w._canonical(e.PLAN['ordinary_pair'][0])

    begin = begin_valid

    def call(self, proposal=None, operation='', n=50):
        obj = e.writer(self.g, n, operation)
        data = proposal or (w._canonical(e.PLAN['faults'][operation]['proposal']) if operation else self.proposal)
        with patch.object(w.http.client, 'HTTPSConnection', self.g.connection), contextlib.redirect_stdout(io.StringIO()):
            result = obj.commit_transition(data, operation)
        return obj, result

    def armed(self):
        journal, pending, candidate = self.begin()
        journal.arm(pending)
        return journal, pending, candidate

    def recovery(self, n=70):
        return j.Journal(e.writer(self.g, n))

    def current(self):
        return self.g.refs[w.REF]

    def d03(self, **kwargs):
        test = e.R3e()
        test.setUp()
        obj, result = test.d03(**kwargs)
        self.g = test.g
        return obj, result

    def terminal(self, pending, candidate):
        return dict(schema=j.SCHEMA, type='TERMINAL', pending=pending,
                    disposition='COMMITTED', observed=candidate,
                    evidence='CANDIDATE_OBSERVED', status=None, request_id=None, d03=None)

    def blocked(self):
        before = self.g.journal_sends
        with self.assertRaises((ValueError, KeyError, OSError, TypeError)):
            self.recovery().recover(self.current)
        self.assertEqual(before, self.g.journal_sends)


class V1(Fixture):
    def test_public_input_keys(self):
        for key in ('repository', 'ref', 'journal', 'history', 'file', 'parent', 'candidate',
                    'gate', 'ALLOW', 'evidence', 'disposition', 'operation', 'delay', 'recovery'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                pc.request({key: 'untrusted'})

    def test_malformed_and_raw_gate_output(self):
        for raw in (b'{', b'null', b'[]', b'{"gate":"ALLOW"}', b'{"history":{}}',
                    b'{"proposal_id":"x","proposal_id":"y"}', b'\xff'):
            with self.subTest(raw=raw):
                obj, result = self.call(raw)
                self.assertFalse(result['update_attempted'])
                self.assertEqual(self.g.authority_sends, 0)
                self.assertNotIn('gate', result)

    def test_no_caller_fault_content(self):
        for key in ('fault', 'duration', 'terminal', 'token', 'source', 'parent', 'evidence', 'delay'):
            bad = dict(e.PLAN['ordinary_pair'][0], **{key: 1})
            self.call(w._canonical(bad))
        self.assertEqual(self.g.journal_sends, 0)

    def test_fixed_operations_once(self):
        journal = self.recovery()
        for operation in (*pc.FAULTS, pc.OUTAGE):
            payload = e.PLAN['infrastructure'] if operation == pc.OUTAGE else e.PLAN['faults'][operation]['proposal']
            journal.consume(journal.operation_binding(w._canonical(payload), operation))
            with self.assertRaises(ValueError):
                self.recovery(900).consume(self.recovery(900).operation_binding(w._canonical(payload), operation))
        self.assertEqual(self.g.authority_sends, 0)

    def test_stale_allow_and_replay(self):
        obj, result = self.call()
        self.assertEqual(result['result'], 'COMMITTED')
        self.assertEqual(self.call()[1]['result'], 'REJECTED')
        self.assertFalse(self.call(w._canonical(result['gate']))[1]['update_attempted'])
        self.assertEqual(self.g.authority_sends, 1)

    def test_normal_proposal_whitespace_is_normatively_bound(self):
        _, result = self.call(json.dumps(e.PLAN['ordinary_pair'][0], indent=2).encode())
        self.assertEqual(result['result'], 'COMMITTED')
        self.recovery().recover(self.current)

    def test_empty_frozen_request_qualified_recovery_only(self):
        obj = e.writer(self.g)
        env = dict(PROOF6_FROZEN_MANIFEST=json.dumps(obj._manifest), GITHUB_EVENT_PATH='offline',
                   GITHUB_RUN_ID='50', GITHUB_RUN_ATTEMPT='1', GITHUB_SHA='a'*40,
                   PROOF6_APP_TOKEN='offline-token', PROOF6_APP_INSTALLATION_ID=str(w.INSTALLATION),
                   PROOF6_APP_SLUG='mc-proof-6-gate-writer')
        with patch.dict(os.environ, env, clear=True), patch.object(ar, 'guard') as guard, \
             patch.object(pc, 'qualify', return_value=e.CALLER) as qualify, \
             patch.object(ar, '_Writer', return_value=obj), patch.object(Path, 'read_text', return_value='{"inputs":{}}'), \
             patch.object(obj, 'commit_transition', side_effect=AssertionError('NO_TRANSITION')), \
             patch.object(obj, '_patch', side_effect=AssertionError('NO_AUTHORITY_SEND')), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ar.main({'writer': None}), 0)
        guard.assert_called_once(); qualify.assert_called_once()
        self.assertEqual(self.g.authority_sends, 0)


class V2(Fixture):
    def test_missing_unreadable_and_lookalike(self):
        self.g.refs[j.REF+'-lookalike'] = self.g.genesis
        del self.g.refs[j.REF]
        self.blocked()

    def test_broken_ancestry(self):
        journal, pending, candidate = self.armed()
        self.g.objects[journal.head]['parents'] = [{'sha': '0'*40}]
        self.blocked()

    def test_unknown_schema(self):
        journal, pending, candidate = self.armed()
        row = self.terminal(pending, candidate); row['schema'] = 'UNKNOWN'
        self.g.refs[j.REF] = self.g.record(row, journal.head)[0]
        self.blocked()

    def test_wrong_operation_and_malformed_terminal(self):
        for field, value in (('pending', '0'*40), ('type', 'REPAIR'), ('observed', 'invalid')):
            self.setUp(); journal, pending, candidate = self.armed()
            row = self.terminal(pending, candidate); row[field] = value
            self.g.refs[j.REF] = self.g.record(row, journal.head)[0]
            self.blocked()

    def test_detached_terminal_cannot_release_old(self):
        journal, pending, candidate = self.armed()
        self.g.record(self.terminal(pending, candidate), journal.head)
        self.blocked()

    def test_duplicate_terminal_blocks_without_repair(self):
        journal, pending, candidate = self.armed(); self.g.refs[w.REF] = candidate
        row = self.terminal(pending, candidate)
        first = self.g.record(row, journal.head)[0]
        self.g.refs[j.REF] = self.g.record(row, first)[0]
        self.blocked()

    def test_terminal_later_in_ancestry(self):
        obj, result = self.call(); terminal = self.g.refs[j.REF]
        journal = self.recovery()
        journal.consume(journal.operation_binding(w._canonical(e.PLAN['infrastructure']), pc.OUTAGE))
        before = self.g.journal_sends
        self.recovery().recover(self.current)
        self.assertIn(terminal, [sha for sha, row in self.recovery().rows])
        self.assertEqual(before, self.g.journal_sends)

    def test_noncanonical_json_and_extra_fields(self):
        for raw in (b'{ "a": 1 }', b'{"a":1,"a":1}', b'{"x":NaN}'):
            with self.assertRaises(ValueError):
                j.parse(raw)


class V3(Fixture):
    def test_old_alone_blocks(self):
        self.armed(); self.blocked()

    def test_unarmed_missing_terminal_is_not_completion_exception(self):
        self.begin(); self.blocked()

    def test_not_committed_candidate_contradiction(self):
        journal, pending, candidate = self.armed()
        journal.finish(pending, w.BASELINE, 'FINAL_REJECTION', 409, 'OFFLINE:REJECTION')
        self.g.refs[w.REF] = candidate
        self.blocked()

    def test_unexpected_third_sha(self):
        self.armed(); self.g.refs[w.REF] = 'e'*40; self.blocked()

    def test_valid_old_rejection_then_legitimate_transition(self):
        self.d03()
        before = self.g.journal_sends
        self.recovery().recover(self.current)
        self.assertEqual(before, self.g.journal_sends)
        self.g.expected_token = 'offline-token'; self.g.status = 200; self.g.error_body = None
        _, result = self.call(n=80)
        self.assertEqual(result['result'], 'COMMITTED')
        self.recovery().recover(self.current)

    def test_skipped_obligation(self):
        journal, pending, candidate = self.armed()
        b = journal.operation_binding(w._canonical(e.PLAN['ordinary_pair'][1]), '')
        row = dict(schema=j.SCHEMA, type='PENDING', binding=b, old=candidate,
                   candidate='e'*40, gate_sha256='a'*64)
        self.g.refs[j.REF] = self.g.record(row, journal.head)[0]
        self.blocked()

    def test_wrong_old_or_candidate_chain(self):
        journal, pending, candidate = self.armed(); self.g.refs[w.REF] = candidate
        self.g.objects[candidate]['parents'] = [{'sha': 'e'*40}]
        self.blocked()

    def test_arbitrary_descendant_not_accepted(self):
        self.call()
        old = self.current()
        self.g.refs[w.REF] = self.g.commit(self.g.objects[old]['tree']['sha'], [old], 'unexplained')
        self.blocked()

    def test_wrong_gate_or_proposal_binding(self):
        for field in ('gate_sha256', 'proposal_sha256'):
            self.setUp(); journal, pending, candidate = self.begin()
            row = copy.deepcopy(journal.pending[pending])
            if field == 'gate_sha256': row[field] = '0'*64
            else: row['binding'][field] = '0'*64
            bad = self.g.record(row, self.g.genesis)[0]
            arm = self.g.record(dict(schema=j.SCHEMA, type='SEND_ARMED', pending=bad), bad)[0]
            self.g.refs[j.REF] = arm; self.g.refs[w.REF] = candidate
            self.blocked()


class V4(Fixture):
    def test_original_lifecycle_crash_boundaries(self):
        for kind in ('CONSUMED', 'PENDING', 'SEND_ARMED', 'AUTHORITY', 'TERMINAL'):
            for when in ('before', 'after'):
                with self.subTest(kind=kind, when=when):
                    self.setUp(); self.g.crash = (when, kind)
                    with self.assertRaises(e.Crash):
                        self.call(operation=pc.FAULTS[0] if kind=='CONSUMED' else '')
                    self.g.crash = None
                    journal = self.recovery()
                    unresolved = set(journal.pending) - journal.resolved
                    if unresolved and (not journal.armed or self.current()==w.BASELINE):
                        self.blocked()
                    else: journal.recover(self.current)
                    self.assertLessEqual(self.g.authority_sends, 1)
                    if kind in ('CONSUMED', 'PENDING', 'SEND_ARMED'):
                        self.assertEqual(self.g.authority_sends, 0)
                    if kind=='CONSUMED' and when=='after':
                        self.assertIn(pc.FAULTS[0], journal.used)

    def test_pending_and_armed_confirmation_loss_no_send(self):
        for kind in ('PENDING', 'SEND_ARMED'):
            self.setUp(); api = self.g.api; lost = [False]
            def fail(token, method, path, body=None):
                if method == 'GET' and '/git/ref/' in path and lost[0]:
                    raise OSError('offline confirmation loss')
                result = api(token, method, path, body)
                if method == 'PATCH' and self.g.row(body['sha'])['type'] == kind:
                    lost[0] = True
                return result
            self.g.api = fail
            _, result = self.call()
            self.assertEqual(self.g.authority_sends, 0)
            self.assertFalse(result['update_attempted'])

    def test_d03_fixed_hook_before_first_confirmation(self):
        obj, result = self.d03()
        self.assertEqual(result['result'], 'INDETERMINATE')
        self.assertEqual(self.g.authority_sends, 1)
        terminal = self.g.refs[j.REF]
        self.assertEqual(self.g.row(terminal)['evidence'], 'FINAL_REJECTION')
        last = self.g.calls[-1]
        self.assertEqual(last[0], 'PATCH')
        self.assertEqual(last[2]['sha'], terminal)
        before = self.g.journal_sends
        self.recovery().recover(self.current)
        self.assertEqual(self.g.journal_sends, before)
        self.assertEqual(result['result'], 'INDETERMINATE')

    def test_stale_confirmation_read(self):
        journal, pending, candidate = self.armed(); self.g.refs[w.REF] = candidate
        parent = journal.head; api = self.g.api; sent = [False]
        # Exact journal endpoint rather than any authority endpoint.
        def stale_ref(token, method, path, body=None):
            result = api(token, method, path, body)
            if method == 'PATCH': sent[0] = True
            if sent[0] and method == 'GET' and path.endswith('/git/ref/' + j.REF.removeprefix('refs/')):
                return dict(ref=j.REF, object=dict(type='commit', sha=parent))
            return result
        self.g.api = stale_ref
        with self.assertRaises(ValueError): self.recovery().recover(self.current)
        self.g.api = api
        before = self.g.journal_sends
        self.recovery().recover(self.current)
        self.assertEqual(before, self.g.journal_sends)

    def test_post_append_partition(self):
        journal, pending, candidate = self.armed(); self.g.refs[w.REF] = candidate
        api = self.g.api; sent = [False]
        def partition(token, method, path, body=None):
            if sent[0]: raise OSError('offline partition')
            result = api(token, method, path, body)
            if method == 'PATCH': sent[0] = True
            return result
        self.g.api = partition
        with self.assertRaises(OSError): self.recovery().recover(self.current)
        self.g.api = api
        self.recovery().recover(self.current)
        self.assertEqual(self.g.authority_sends, 0)

    def test_explicit_and_ambiguous_journal_patch(self):
        for mode in (None, 'child', 'old'):
            self.setUp(); journal, pending, candidate = self.armed()
            self.g.refs[w.REF] = candidate; self.g.ambiguity = mode
            before = self.g.journal_sends
            if mode == 'old':
                with self.assertRaises(ValueError): self.recovery().recover(self.current)
            else: self.recovery().recover(self.current)
            self.assertEqual(self.g.journal_sends, before + 1)

    def test_crash_after_completion_patch(self):
        journal, pending, candidate = self.armed(); self.g.refs[w.REF] = candidate
        self.g.crash = ('after', 'TERMINAL')
        with self.assertRaises(e.Crash): self.recovery().recover(self.current)
        self.g.crash = None
        before = self.g.journal_sends; self.recovery().recover(self.current)
        self.assertEqual(before, self.g.journal_sends)


class V5(Fixture):
    def test_normal_transition_cannot_run_sibling_hook(self):
        self.call()
        self.call(operation=pc.FAULTS[2], n=51)
        state = self.w._history(self.current())[2]['state_sha256']
        proposal = dict(e.PLAN['ordinary_pair'][1], expected_state_sha256=state)
        with patch.object(sibling_canary, 'recover_d07', side_effect=AssertionError('NO_NORMAL_CANARY')):
            _, result = self.call(w._canonical(proposal), n=80)
        self.assertEqual(result['result'], 'COMMITTED')

    def test_existing_terminal_read_only(self):
        self.call(); before = self.g.journal_sends
        for n in (60, 61, 62): self.recovery(n).recover(self.current)
        self.assertEqual(before, self.g.journal_sends)
        self.assertEqual(self.g.authority_sends, 1)

    def test_h0_and_h1_same_parent(self):
        for prior in (False, True):
            self.setUp(); journal, pending, candidate = self.armed()
            self.g.refs[w.REF] = candidate; parent = journal.head
            if prior:
                self.g.ambiguity = 'old'
                with self.assertRaises(ValueError): self.recovery(60).recover(self.current)
                self.g.ambiguity = None
            self.recovery(61).recover(self.current)
            self.assertEqual(self.g.objects[self.g.refs[j.REF]]['parents'], [{'sha': parent}])
            self.assertEqual(self.g.authority_sends, 0)

    def test_each_sibling_winner_and_orphan(self):
        for winner in (0, 1):
            self.setUp(); journal, pending, candidate = self.armed()
            self.g.refs[w.REF] = candidate
            row = self.terminal(pending, candidate)
            tree = self.g.tree(self.g.blob(w._canonical(row)))
            children = [self.g.commit(tree, [journal.head], label) for label in ('first', 'second')]
            self.assertNotEqual(*children)
            self.g.advance(j.REF, children[winner])
            with self.assertRaises(urllib.error.HTTPError): self.g.advance(j.REF, children[1-winner])
            before = self.g.journal_sends
            self.recovery().recover(self.current)
            self.assertEqual(before, self.g.journal_sends)
            self.assertEqual(self.g.refs[j.REF], children[winner])

    def test_d07_fixed_delayed_first_path_and_future_read_only(self):
        self.assertEqual(self.call()[1]['result'], 'COMMITTED')
        obj, result = self.call(operation=pc.FAULTS[2], n=51)
        self.assertEqual(result['result'], 'INDETERMINATE')
        self.assertEqual(self.g.authority_sends, 2)
        self.assertFalse(result['response_consumed'])
        before = self.g.journal_sends
        recovery = e.writer(self.g, 70)
        with patch.object(recovery, '_patch', side_effect=AssertionError('NO_AUTHORITY_TRANSPORT')), \
             patch.object(j.Journal, 'arm', side_effect=AssertionError('NO_ARM')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            recovered = recovery.recover_only()
        self.assertEqual(recovered['result'], 'RECOVERY_CONFIRMED')
        self.assertEqual(self.g.journal_sends, before + 2)
        self.assertIn('PROOF6_SIBLING_CANARY', output.getvalue())
        self.assertIsNone(recovery._transport_candidate)
        e.writer(self.g, 71).recover_only()
        self.assertEqual(self.g.journal_sends, before + 2)
        self.assertEqual(self.g.authority_sends, 2)
        self.assertEqual(result['result'], 'INDETERMINATE')

    def test_safety_equivalence_all_fields(self):
        journal, pending, candidate = self.armed()
        row = self.terminal(pending, candidate); p = journal.pending[pending]
        original = j.terminal_semantics(journal.head, row, p, journal.arms[pending])
        for key in row:
            changed = copy.deepcopy(row); changed[key] = 'changed'
            with self.subTest(field=key):
                try: altered = j.terminal_semantics(journal.head, changed, p, journal.arms[pending])
                except ValueError: continue
                self.assertNotEqual(original, altered)
        for key in p:
            changed = copy.deepcopy(p); changed[key] = 'changed'
            self.assertNotEqual(original, j.terminal_semantics(journal.head, row, changed, journal.arms[pending]))
        self.assertNotEqual(original, j.terminal_semantics('0'*40, row, p, journal.arms[pending]))
        self.assertNotEqual(original, j.terminal_semantics(journal.head, row, p, '0'*40))

    def test_every_nested_d03_safety_leaf_compares_unequal(self):
        self.d03()
        journal = self.recovery()
        pending = next(iter(journal.pending))
        _, parent, row = journal.terminals[pending]
        operation = journal.pending[pending]
        original = j.terminal_semantics(parent, row, operation, journal.arms[pending])
        def paths(value, path=()):
            if isinstance(value, dict):
                for key, child in value.items(): yield from paths(child, path+(key,))
            else: yield path
        cases = 0
        for which, value in (('terminal', row), ('operation', operation)):
            for path in paths(value):
                changed = copy.deepcopy(value); cursor = changed
                for key in path[:-1]: cursor = cursor[key]
                cursor[path[-1]] = 'changed-safety-value'
                with self.subTest(which=which, path=path):
                    try:
                        result = j.terminal_semantics(parent, changed if which=='terminal' else row,
                            changed if which=='operation' else operation, journal.arms[pending])
                    except ValueError: pass
                    else: self.assertNotEqual(result, original)
                cases += 1
        self.assertGreater(cases, 60)

    def test_invalid_winner_at_admitted_boundary(self):
        for change in ({'pending':'0'*40}, {'disposition':'NOT_COMMITTED'}, {'evidence':'UNARMED'}, {'status':403}):
            self.setUp(); journal, pending, candidate = self.armed(); self.g.refs[w.REF] = candidate
            row = dict(self.terminal(pending, candidate), **change)
            def wrong(): self.g.refs[j.REF] = self.g.record(row, journal.head)[0]
            before = self.g.journal_sends
            with patch.object(j.Journal, '_completion_boundary', side_effect=wrong), self.assertRaises(ValueError):
                self.recovery().recover(self.current)
            self.assertEqual(self.g.journal_sends, before + 1)
            self.blocked()

    def test_changed_head_before_admission_blocks(self):
        journal, pending, candidate = self.armed(); self.g.refs[w.REF] = candidate
        self.g.refs[j.REF] = self.g.record(dict(j.GENESIS, extra='invalid'), journal.head)[0]
        self.blocked()

    def test_completion_loser_after_legitimate_descendants(self):
        journal, pending, candidate = self.armed(); self.g.refs[w.REF] = candidate
        row = self.terminal(pending, candidate)
        orphan = self.g.record(row, journal.head)[0]
        self.recovery().recover(self.current)
        next_proposal = dict(e.PLAN['ordinary_pair'][1], expected_state_sha256=self.w._history(candidate)[2]['state_sha256'])
        self.assertEqual(self.call(w._canonical(next_proposal), n=90)[1]['result'], 'COMMITTED')
        with self.assertRaises(urllib.error.HTTPError): self.g.advance(j.REF, orphan)
        before = self.g.journal_sends; self.recovery().recover(self.current)
        self.assertEqual(before, self.g.journal_sends)

    def test_delayed_completion_confirmation_after_later_authority_advance(self):
        journal, pending, candidate = self.armed(); self.g.refs[w.REF] = candidate
        row = self.terminal(pending, candidate)
        def later_work():
            self.g.refs[j.REF] = self.g.record(row, journal.head)[0]
            proposal = dict(e.PLAN['ordinary_pair'][1], expected_state_sha256=self.w._history(candidate)[2]['state_sha256'])
            self.assertEqual(self.call(w._canonical(proposal), n=90)[1]['result'], 'COMMITTED')
        with patch.object(j.Journal, '_completion_boundary', side_effect=later_work):
            observed = self.recovery().recover(self.current)
        self.assertEqual(observed, self.current())
        self.assertNotEqual(observed, candidate)

    def test_d07_delayed_authority_send_old_blocks_before_admission(self):
        self.call()
        before = self.g.authority_sends
        self.g.delay = True
        obj, result = self.call(operation=pc.FAULTS[2], n=51)
        self.assertEqual(result['result'], 'INDETERMINATE')
        self.assertEqual(self.g.authority_sends, before + 1)
        self.blocked()
        self.assertEqual(self.g.authority_sends, before + 1)

    def test_replay_d03_after_readonly_recovery_cannot_resend(self):
        obj, result = self.d03()
        self.recovery().recover(self.current)
        before = self.g.authority_sends
        _, replay = self.call(operation=pc.FAULTS[1], n=80)
        self.assertNotIn('gate', replay)
        self.assertEqual(self.g.authority_sends, before)


class V6(Fixture):
    def test_d03_body_limit_then_readonly_recovery(self):
        body = b'{"message":"Resource not accessible by integration"}'
        body += b' ' * (e.dr.BODY_LIMIT - len(body))
        obj, result = self.d03(body=body)
        self.assertEqual(result['result'], 'INDETERMINATE')
        self.assertEqual(len(self.g.row(self.g.refs[j.REF])['d03']['response']['body'].encode()), 4096)
        before = self.g.journal_sends; self.recovery().recover(self.current)
        self.assertEqual(before, self.g.journal_sends)

    def test_credential_and_classifier_regressions_bound_to_real_paths(self):
        # Existing retained suite separately exercises all detailed malformed
        # worker/framing cases. Here assert original failure and recovery linkage.
        for token in ('', 'offline-token', 'with space'):
            self.setUp(); obj, result = self.d03(env_change={'PROOF6_D03_JOB_TOKEN':token})
            self.assertEqual(self.g.authority_sends, 0)
            self.assertNotEqual(result.get('d03_result'), 'PASS')

    def test_d03_readonly_receipt_optional_request_id(self):
        test = e.R3e(); test.setUp(); test.g.headers['x-github-request-id'] = None
        obj, result = test.d03(); self.g = test.g
        self.assertEqual(result['result'], 'INDETERMINATE')
        self.recovery().recover(self.current)
        self.assertIsNone(self.g.row(self.g.refs[j.REF])['request_id'])

    def test_d04_fixed_window_after_setup_delay(self):
        clock = [75.0]; events = []; libc = Mock(); libc.unshare.return_value = 0
        def sleep(seconds): clock[0] += seconds
        with patch.object(e.outage.time, 'monotonic', side_effect=lambda:clock[0]), \
             patch.object(e.outage.time, 'sleep', side_effect=sleep), \
             patch.object(e.outage.ctypes, 'CDLL', return_value=libc), \
             patch.object(e.outage, 'isolated', return_value={'api_github_connection':'unavailable'}):
            result = e.outage.isolate_runtime(events.append)
        self.assertEqual(clock[0], 105.0)
        self.assertEqual(e.outage.WINDOW_SECONDS, 30); self.assertEqual(e.outage.MAX_SECONDS, 120)
        self.assertEqual([r['phase'] for r in events], ['START','READY','END'])
        self.assertEqual({r['pid'] for r in events}, {os.getpid()})
        self.assertEqual(result['result'], 'OUTAGE_COMPLETED')

    def test_app_probes_fixed_targets_and_unexpected_success(self):
        for success in (None, 'F02', 'F10'):
            self.setUp(); api = self.g.api; probes = []
            self.g.objects['a'*40] = dict(sha='a'*40, tree=self.g.objects[w.BASELINE]['tree'], parents=[])
            def transport(token, method, path, body=None):
                if method == 'GET' and path.endswith('/git/ref/heads/proof6-writer-runtime-r3f'):
                    return dict(ref=app_probes.RUNTIME, object={'sha':'a'*40})
                if method == 'PUT' or (method == 'PATCH' and path.endswith('/git/refs/heads/proof6-writer-runtime-r3f')):
                    name = 'F02' if method == 'PUT' else 'F10'; probes.append((name, path, body))
                    if success == name: return {}
                    raise urllib.error.HTTPError('offline', 403, 'forbidden',
                        {'x-github-request-id':'OFFLINE:PROBE'}, io.BytesIO(b'{"message":"Resource not accessible by integration"}'))
                return api(token, method, path, body)
            self.g.api = transport
            obj, result = self.call(operation=pc.FAULTS[0])
            self.assertEqual(self.g.authority_sends, 0)
            self.assertEqual(probes[0][1], j.BASE+'/rulesets/22725076')
            self.assertEqual(probes[0][2]['enforcement'], 'disabled')
            if success == 'F02': self.assertEqual(len(probes), 1)
            else:
                self.assertEqual(len(probes), 2)
                self.assertFalse(probes[1][2]['force'])
                child = self.g.objects[probes[1][2]['sha']]
                self.assertEqual(child['parents'], [{'sha':'a'*40}])
                self.assertEqual(child['tree'], self.g.objects['a'*40]['tree'])
            self.assertEqual(result['app_probe_result'], 'FAIL' if success else 'NEGATIVE_RESPONSES_RECORDED')

    def test_plan_72_and_budget(self):
        plan, _ = pc.plan()
        expected = {f'{group}{n:02}' for group, count in zip('ABCDEFGH', (9,12,11,9,6,14,3,8)) for n in range(1,count+1)}
        self.assertEqual(len(plan['cases']), 72)
        self.assertEqual({r['id'] for r in plan['cases']}, expected)
        self.assertEqual(sum(r['reason']=='FRESH_R3F' for r in plan['cases']), 56)
        self.assertEqual(sum(r['reason']=='NO_VALID_PRIOR_EVIDENCE_SO_FRESH' for r in plan['cases']), 16)
        self.assertTrue(all(r['disposition']=='FRESH' and r['method'] for r in plan['cases']))
        self.assertEqual(plan['workflow_budget'], dict(setup_bootstrap=1, ordinary=3, fault=4, recovery=2,total=10))
        self.assertEqual(set(plan['faults']), set(pc.FAULTS))
        self.assertEqual(plan['max_consumptions_per_operation'], 1)
        self.assertEqual(plan['recovery']['completion_requests_in_R7'], 2)

    def test_fixed_proposal_sequence_accepted_gate(self):
        a, b = e.PLAN['ordinary_pair']
        da = self.w._gate.decide(e.HISTORY, a); db = self.w._gate.decide(e.HISTORY, b)
        self.assertEqual(da['decision'], 'ALLOW'); self.assertEqual(db['decision'], 'ALLOW')
        for first in (da, db):
            history = dict(version=1, events=e.HISTORY['events']+[first['candidate_event']])
            decision = self.w._gate.decide(history, e.PLAN['faults'][pc.FAULTS[2]]['proposal'])
            self.assertEqual(decision['decision'], 'ALLOW')

    def test_accepted_bytes_and_build_inventory(self):
        for name in ('proofs/proof1/replay.py','proofs/proof2/gate.py','proofs/proof6/d03_rejection.py',
                     'proofs/proof6/admission.py','proofs/proof6/reconcile.py','proofs/proof6/diagnostics.py',
                     'proofs/proof6/diagnostic-bindings.json','proofs/proof6/ruleset_view.py'):
            self.assertEqual((ROOT/name).read_bytes(), subprocess.check_output(['git','-C',str(ROOT),'show',e.PLAN['source_base']['commit']+':'+name]))
        inventory = json.loads((ROOT/'proofs/proof6/build.json').read_bytes())
        for name, digest in inventory.items(): self.assertEqual(w._digest((ROOT/name).read_bytes()), digest)

    def test_no_recovery_authority_or_permit_calls(self):
        for function in (w._Writer.recover_only, j.Journal.recover, j.Journal.reconcile, sibling_canary.recover_d07):
            import inspect
            source = inspect.getsource(function)
            for forbidden in ('._patch(', '.arm(', '.take_send(', '.commit_transition('):
                self.assertNotIn(forbidden, source)
        self.assertEqual(list(j.FIELDS), ['CONSUMED','PENDING','SEND_ARMED','TERMINAL'])
        self.assertNotIn('recover_d07', __import__('inspect').getsource(w._Writer.commit_transition))


if __name__ == '__main__':
    with patch.object(socket, 'socket', side_effect=AssertionError('OFFLINE_ONLY')):
        unittest.main(verbosity=2)
