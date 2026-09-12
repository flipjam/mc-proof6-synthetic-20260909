"""Run every still-applicable retained R3e assertion against candidate bytes.
Superseded assertions remain byte-identical in legacy_r3e.py; each has an
explicit R3f requirement/replacement below. No production behavior is patched.
"""
import json
from support import legacy as e, suite

SUPERSEDED = {
    'test_pending_crash_unarmed_resolution': 'V3.test_unarmed_missing_terminal_is_not_completion_exception: exact SEND_ARMED parent required',
    'test_delayed_arming_loses_to_resolution': 'V3.test_unarmed_missing_terminal_is_not_completion_exception: no repeated UNARMED recovery completion',
    'test_reused_candidate_blocked': 'V1.test_stale_allow_and_replay and V3.test_unarmed_missing_terminal_is_not_completion_exception',
    'test_crash_boundaries': 'V4 confirmation/crash tests and V3 unarmed missing-terminal BLOCK; old test expects unarmed auto-resolution',
    'test_d07_unknown_no_response_read_no_resend': 'V5.test_d07_fixed_delayed_first_path_and_future_read_only: D07 now follows one O1/O2 winner',
    'test_delayed_patch_blocks_before_gate': 'V3.test_old_alone_blocks plus V5 D07 path; old D07 baseline proposal is no longer admitted',
    'test_unchanged_accepted_architecture': 'V6.test_accepted_bytes_and_build_inventory: D04 timing intentionally changes; all protected unchanged mechanisms compared to exact R3e',
    'test_successor_plan_and_real_gate_roadmap6': 'V6.test_fixed_proposal_sequence_accepted_gate: D07 follows roadmap-7 winner',
    'test_exact_rejection_finalizes_immediately_and_stops': 'V4.test_d03_fixed_hook_before_first_confirmation: original must remain INDETERMINATE',
    'test_request_id_optional_but_recorded_when_present': 'V6.test_d03_readonly_receipt_optional_request_id: same receipt after read-only recovery',
    'test_replay_and_second_patch_rejected': 'V1.test_fixed_operations_once plus V5 existing-terminal/recovery no resend',
    'test_real_exact_content_length_qualifies_and_replays': 'V4.test_d03_fixed_hook_before_first_confirmation: same real HTTP parser, original INDETERMINATE then confirmed recovery',
    'test_real_exact_body_limit_can_qualify': 'V6.test_d03_body_limit_then_readonly_recovery: original confirmation intentionally lost',
    'test_plan_and_all_other_source_are_v1_byte_identical': 'V6.test_accepted_bytes_and_build_inventory and full source inventory: R3f is a successor, not R3e V2',
}


if __name__ == '__main__':
    original = list(suite())
    selected = [test for test in original if test._testMethodName not in SUPERSEDED]
    assert len(original) == 123 and len(selected) == 109
    print(json.dumps({'original_tests':123, 'applicable_unchanged_assertions':109,
                      'superseded':SUPERSEDED}, sort_keys=True), flush=True)
    with e.patch.object(e.socket, 'socket', side_effect=AssertionError('OFFLINE_ONLY')):
        result = e.unittest.TextTestRunner(verbosity=2).run(e.unittest.TestSuite(selected))
    raise SystemExit(not result.wasSuccessful())
