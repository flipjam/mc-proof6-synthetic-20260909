"""198 retained assertions, with eight explicitly mapped D04 replacements.
Original test files stay byte-identical. Only successor identity literals in
test_r3f.py are adapted in memory, plus support.py's prior-step setup fixture.
"""
import json
from pathlib import Path
import socket
import sys
import types
import unittest
from unittest.mock import patch
import support
import regression

original = types.ModuleType('test_r3f')
sys.modules['test_r3f'] = original
raw = Path(__file__).with_name('test_r3f.py').read_text()
raw = raw.replace('proof6-writer-runtime-r3f', 'proof6-writer-runtime-r3g').replace('FRESH_R3F','FRESH_R3G')
exec(compile(raw, 'test_r3f.py (R3g identity adapter)', 'exec'), original.__dict__)
import test_caller_types
import reviewer_regression

REPLACEMENTS = {
 'test_d04_same_runtime_process_structure':'ActualProcess.test_shared_actual_process_structure',
 'test_helper_only_isolation_fails':'Predicate.test_non_loopback_interface',
 'test_d04_unshare_and_observations_same_pid':'ActualProcess.test_actual_pid_and_30_second_window',
 'test_d04_unshare_failure_blocks':'ActualProcess.test_actual_failure_has_no_ready_or_end',
 'test_d04_main_consumes_then_isolates_actual_runtime':'Admission.test_pass_precedes_consumption_and_actual_isolation',
 'test_d04_isolation_evidence_still_required':'ActualProcess.test_end_rechecks_and_failure_cannot_complete',
 'test_native_normal_completion_marker_requires_child_success':'ActualProcess.test_native_supervisor_success_and_failure',
 'test_d04_fixed_window_after_setup_delay':'ActualProcess.test_actual_pid_and_30_second_window',
}


def suite():
    result = unittest.TestSuite()
    legacy = [t for t in support.suite() if t._testMethodName not in regression.SUPERSEDED]
    candidate = [cls(name) for cls in (original.V1,original.V2,original.V3,original.V4,original.V5,original.V6)
                 for name in cls.__dict__ if name.startswith('test_')]
    assert len(legacy)==109 and len(candidate)==53
    all_prior = legacy + candidate
    assert {t._testMethodName for t in all_prior if t._testMethodName in REPLACEMENTS} == set(REPLACEMENTS)
    result.addTests(t for t in all_prior if t._testMethodName not in REPLACEMENTS)
    result.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(test_caller_types.CallerTypes))
    reviewer = reviewer_regression
    names = [n for n in reviewer.module.Review.__dict__ if n.startswith('test_')]
    result.addTests(reviewer.module.Review(n) for n in names if n not in reviewer.SUPERSEDED)
    result.addTests(reviewer.R3fConfirmation(n) for n in reviewer.SUPERSEDED)
    assert result.countTestCases() == 198
    return result


if __name__ == '__main__':
    print(json.dumps({'baseline':206,'retained':198,'explicit_replacements':REPLACEMENTS},sort_keys=True),flush=True)
    tests = list(suite())
    # The reviewer alone needs local socketpair. Block socket creation in the
    # other 168 retained tests, exactly as their original offline runners do.
    with patch.object(socket,'socket',side_effect=AssertionError('OFFLINE_ONLY')):
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(tests[:168]))
    reviewer = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(tests[168:]))
    sys.exit(not (result.wasSuccessful() and reviewer.wasSuccessful()))
