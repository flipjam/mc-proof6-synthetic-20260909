"""Fixed D07 recovery-only sibling ordering within the sole hosted job.

Two independent calls of production Journal.recover, one PATCH each. The first
call pauses at the admitted internal transport boundary; the second completes;
then the delayed first request reaches the provider. No thread, worker, network
fault API, caller selector, lock, authority transport or extra workflow exists.
"""
from journal import Journal
from writer import _canonical, _require


def recover_d07(writer):
    current = writer._current_authority
    receipts = []

    class DelayedFirst(Journal):
        _completion_label = 'd07-delayed-first'

        def _completion_boundary(self):
            second = Journal(writer)
            expected, pending = second.reconcile(current)
            _require(pending is not None and second.head == self.head
                     and second.pending[pending]['binding']['operation'] == 'D07_DROP_PATCH_RESPONSE')
            second.recover(current, receipts.append)

    first = DelayedFirst(writer)
    expected, pending = first.reconcile(current)
    _require(pending is not None and first.pending[pending]['binding']['operation'] == 'D07_DROP_PATCH_RESPONSE')
    result = first.recover(current, receipts.append)
    completions = [r for r in receipts if r['phase'] == 'TERMINAL_COMPLETION_CONFIRMED']
    _require(len(completions) == 2 and completions[0]['candidate_canonical'] is True
             and completions[1]['candidate_canonical'] is False
             and completions[0]['canonical_terminal'] == completions[1]['canonical_terminal'])
    print('PROOF6_SIBLING_CANARY ' + _canonical(dict(
        recovery_run=writer._receipt_binding, receipts=receipts,
        authority_sha=expected, authority_patch_count=0)).decode(), flush=True)
    return result
