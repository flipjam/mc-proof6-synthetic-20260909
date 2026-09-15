import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from fixtures import *


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.guard = patch.object(socket, 'socket', side_effect=AssertionError('OFFLINE_ONLY'))
        self.guard.start()
        self.addCleanup(self.guard.stop)
        self.c = config()
        self.p = Fake(self.c)
        self.b = Broker(self.c, self.p)
        self.proposal = intent()

    def send(self, p=None):
        return self.b.submit(canonical(self.proposal if p is None else p))

    def invalid(self, **extra):
        p = dict(self.proposal, **extra)
        self.assertEqual(self.send(p)['result'], 'BLOCKED')
        self.assertEqual((self.p.sends, self.p.journal_sends), (0, 0))

    def test_valid_internal_allow_and_exact_binding(self):
        self.assertEqual(self.send()['result'], 'INDETERMINATE')
        j = Journal(self.p, self.c)
        self.assertEqual(j.stage, 'SEND_ARMED')
        self.assertEqual(j.auth['proposal_sha256'], digest(self.proposal))
        self.assertEqual(j.auth['operation_class'], 'NON_FORCE_FAST_FORWARD')
        self.assertEqual(self.p.sends, 1)

    def test_reject_zero_transport(self):
        self.proposal['expected_state_sha256'] = '0'*64
        self.assertEqual(self.send()['result'], 'REJECT')
        self.assertEqual((self.p.sends, self.p.journal_sends), (0, 0))

    def test_unknown(self): self.invalid(extra=True)
    def test_repository_injection(self): self.invalid(repository='flipjam/mission-control')
    def test_repository_id_injection(self): self.invalid(repository_id=1)
    def test_ref_injection(self): self.invalid(ref='refs/heads/main')
    def test_candidate_injection(self): self.invalid(candidate_sha='f'*40)
    def test_approval_injection(self): self.invalid(approval={'decision': 'ALLOW'})
    def test_allow_injection(self): self.invalid(decision='ALLOW')
    def test_authorization_injection(self): self.invalid(authorization={'schema': 'BMIN_AUTHORIZED_TRANSITION_V1'})
    def test_force_injection(self): self.invalid(force=True)
    def test_fault_injection(self): self.invalid(scenario='OTHER')
    def test_credentials_injection(self): self.invalid(writer_token='inert-test-string')
    def test_operation_id_injection(self): self.invalid(operation_id='fresh')
    def test_raw_command_injection(self): self.invalid(command='git push')
    def test_policy_injection(self): self.invalid(policy_sha256='f'*64)

    def test_missing_fields(self):
        for key in self.proposal:
            p = dict(self.proposal)
            del p[key]
            self.assertEqual(self.send(p)['result'], 'BLOCKED')
        self.assertEqual(self.p.sends, 0)

    def test_type_confusion(self):
        for value in (True, False, '0', None, 0.0, [], {}):
            self.assertEqual(self.send(dict(self.proposal, expected_baton=value))['result'], 'BLOCKED')
        self.assertEqual(self.p.sends, 0)

    def test_duplicate_json_key(self):
        raw = canonical(self.proposal)[:-1] + b',"action":"ADVANCE_ROADMAP"}'
        self.assertEqual(self.b.submit(raw)['result'], 'BLOCKED')
        self.assertEqual(self.p.sends, 0)

    def test_non_json_and_oversized(self):
        for raw in (b'{}', b'null', b'NaN', b'{}'*3000, b'\xff', 'text'):
            self.assertEqual(self.b.submit(raw)['result'], 'BLOCKED')
        self.assertEqual(self.p.sends, 0)

    def test_canonical_whitespace_same_operation(self):
        self.send()
        self.b.submit(json.dumps(self.proposal, indent=2).encode())
        self.assertEqual(self.p.sends, 1)

    def test_state_stale_before_send(self):
        self.p.on_check = lambda p: p.refs.update({AUTHORITY: 'f'*40}) if p.checks == 2 else None
        self.assertEqual(self.send()['result'], 'NO_SEND')
        self.assertEqual(self.p.sends, 0)

    def test_policy_stale_before_send(self):
        self.p.on_check = lambda p: p.c.update(policy_sha256='f'*64) if p.checks == 2 else None
        self.assertEqual(self.send()['result'], 'NO_SEND')
        self.assertEqual(self.p.sends, 0)

    def test_runtime_stale_before_send(self):
        self.p.on_check = lambda p: p.refs.update({RUNTIME: 'f'*40}) if p.checks == 2 else None
        self.assertEqual(self.send()['result'], 'NO_SEND')
        self.assertEqual(self.p.sends, 0)

    def test_writer_configuration_mismatch(self):
        self.p.c['installation_id'] += 1
        self.assertEqual(self.send()['result'], 'BLOCKED')
        self.assertEqual(self.p.sends, 0)

    def test_gate_source_mismatch(self):
        self.c['source_hashes']['proofs/proof2/gate.py'] = 'f'*64
        with self.assertRaises(ValueError): Broker(self.c, self.p)
        self.assertEqual(self.p.sends, 0)

    def test_target_configuration_cannot_redirect(self):
        self.c['authority_ref'] = 'refs/heads/main'
        with self.assertRaises(ValueError): Broker(self.c, self.p)

    def test_unresolved_prior_blocks_every_proposal(self):
        self.p.send_effect = 'old'
        self.send()
        self.proposal['expected_baton'] = 1
        self.assertEqual(self.send()['result'], 'BLOCKED_SPENT_OR_PENDING')
        self.assertEqual(self.p.sends, 1)

    def test_same_invocation_never_resends(self):
        self.send()
        for _ in range(3): self.send()
        self.assertEqual(self.p.sends, 1)

    def test_dropped_response_keeps_armed(self):
        self.assertEqual(self.send()['result'], 'INDETERMINATE')
        self.assertEqual(Journal(self.p, self.c).stage, 'SEND_ARMED')

    def test_recovery_candidate_commits_without_send(self):
        self.send()
        self.assertEqual(Broker(self.c, self.p).reconcile()['result'], 'COMMITTED')
        self.assertEqual(Journal(self.p, self.c).stage, 'TERMINAL')
        self.assertEqual(self.p.sends, 1)

    def test_recovery_conflict_blocks(self):
        self.p.send_effect = 'conflict'
        self.send()
        self.assertEqual(Broker(self.c, self.p).reconcile()['result'], 'BLOCKED_CONFLICT')
        self.assertEqual(self.p.sends, 1)

    def test_old_is_not_definitive_rejection(self):
        self.p.send_effect = 'old'
        self.send()
        self.assertEqual(self.b.reconcile()['result'], 'BLOCKED_UNRESOLVED')
        self.assertEqual(Journal(self.p, self.c).stage, 'SEND_ARMED')
        self.assertEqual(self.p.sends, 1)

    def test_terminal_replay_returns_prior_result(self):
        self.send()
        self.b.reconcile()
        result = self.send()
        self.assertEqual(result, dict(result='COMMITTED', replay=True, authority_send=False))
        self.assertEqual(self.p.sends, 1)

    def test_new_valid_proposal_cannot_reopen_one_shot(self):
        self.send()
        self.b.reconcile()
        p = intent(self.p.objects[self.p.refs[AUTHORITY]][1])
        self.assertEqual(self.send(p)['result'], 'BLOCKED_SPENT_OR_PENDING')
        self.assertEqual(self.p.sends, 1)

    def test_malformed_journal(self):
        self.p.objects[self.c['journal_genesis_sha']] = ([], {'schema': 'broken'})
        self.assertEqual(self.send()['result'], 'BLOCKED')
        self.assertEqual(self.p.sends, 0)

    def test_fabricated_auth_in_journal(self):
        self.send()
        j = Journal(self.p, self.c)
        self.p.objects[j.records[0][0]][1]['authorization']['candidate_sha'] = 'f'*40
        self.assertEqual(self.b.reconcile()['result'], 'BLOCKED')
        self.assertEqual(self.p.sends, 1)

    def test_missing_journal_ancestor(self):
        self.send()
        del self.p.objects[self.c['journal_genesis_sha']]
        self.assertEqual(self.b.reconcile()['result'], 'BLOCKED')
        self.assertEqual(self.p.sends, 1)

    def test_candidate_wrong_parent(self):
        self.send()
        sha = self.p.refs[AUTHORITY]
        self.p.objects[sha] = (['f'*40], self.p.objects[sha][1])
        self.assertEqual(self.b.reconcile()['result'], 'BLOCKED')

    def test_unexpected_provider_result_stays_armed(self):
        self.p.result = {'decision': 'ALLOW', 'result': 'COMMITTED'}
        self.assertEqual(self.send()['result'], 'BLOCKED_UNEXPECTED_PROVIDER_RESULT')
        self.assertEqual(Journal(self.p, self.c).stage, 'SEND_ARMED')
        self.send()
        self.assertEqual(self.p.sends, 1)

    def test_transport_exception_never_resends(self):
        self.p.send_effect = 'raise'
        self.assertEqual(self.send()['result'], 'INDETERMINATE')
        self.send()
        self.assertEqual(self.p.sends, 1)

    def test_crash_after_prepared_recovery_no_send(self):
        a, plan = authorize(self.c, self.proposal, self.c['initial_authority_sha'], history())
        self.p.create(plan)
        Journal(self.p, self.c).prepare(self.proposal, a)
        self.assertEqual(self.b.reconcile()['result'], 'NO_SEND')
        self.assertEqual(self.send()['result'], 'NO_SEND')
        self.assertEqual(self.p.sends, 0)

    def test_arm_append_loss_cannot_release_transport(self):
        def lose(p, plan):
            if plan['value']['stage'] == 'SEND_ARMED': raise ConnectionError()
        self.p.on_append = lose
        self.send()
        self.assertEqual(Journal(self.p, self.c).stage, 'SEND_ARMED')
        self.p.on_append = None
        self.send()
        self.assertEqual(self.p.sends, 0)

    def test_change_after_arming_blocks(self):
        self.p.on_check = lambda p: p.refs.update({AUTHORITY: 'f'*40}) if p.checks == 3 else None
        self.send()
        self.assertEqual(Journal(self.p, self.c).stage, 'SEND_ARMED')
        self.assertEqual(self.p.sends, 0)

    def test_naive_old_equals_safe_retry_counterexample(self):
        self.p.send_effect = 'old'
        self.send()
        # Naive recovery equates currently old with permission to retry.
        naive_retry = self.p.ref(AUTHORITY) == self.c['initial_authority_sha']
        self.assertTrue(naive_retry)
        self.b.reconcile()
        self.send()
        self.assertEqual(self.p.sends, 1)

    def test_fresh_os_process_recovery_and_replay(self):
        self.send()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'provider.json'
            self.p.save(path)
            program = ("import sys,socket; socket.socket=lambda *a,**k: (_ for _ in ()).throw(AssertionError('OFFLINE')); "
                       "sys.path.insert(0,sys.argv[1]); from fixtures import *; p=Fake.restore(sys.argv[2]); "
                       "b=Broker(p.c,p); assert b.reconcile()['result']=='COMMITTED'; "
                       "assert b.submit(canonical(intent()))['result']=='COMMITTED'; "
                       "assert p.sends==1; p.save(sys.argv[2])")
            subprocess.run([sys.executable, '-I', '-B', '-c', program, str(Path(__file__).parent), str(path)],
                           check=True, capture_output=True, timeout=30)
            fresh = Fake.restore(path)
            self.assertEqual(fresh.sends, 1)
            self.assertEqual(Journal(fresh, self.c).stage, 'TERMINAL')


if __name__ == '__main__': unittest.main(verbosity=2)
