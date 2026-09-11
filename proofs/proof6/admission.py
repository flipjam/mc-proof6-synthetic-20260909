"""GET/log-only admission. Run numbers identify the interval, never execution order."""
import hashlib
import json
import re

from reconcile import disposition


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def require(condition):
    if not condition:
        raise ValueError('ADMISSION_BLOCKED')


def binding(manifest, run_id, attempt, runtime_sha):
    return {'manifest_sha256': None if manifest is None else hashlib.sha256(canonical(manifest)).hexdigest(),
            'run_id': run_id, 'run_attempt': attempt, 'runtime_sha': runtime_sha}


def blocked(identity):
    return dict(identity, result='BLOCKED', update_attempted=False,
                old_sha=None, candidate_commit=None, new_sha=None,
                remote_outcome='not_attempted', phase='before_writer')


def records(raw):
    result = []
    for line in raw.splitlines():
        # Require a complete JSON suffix; shell source text is not a receipt.
        match = re.search(r'\b(PROOF6_PENDING|PROOF6_RESULT|PROOF6_RECONCILIATION|PROOF6_CONSUMPTION) (\{.*\})$', line)
        if match:
            result.append((match[1], json.loads(match[2])))
    return result


def admit(manifest, current_id, runs, read_log, reconcile, emit,
          requested_operation='', observe=lambda item: None):
    first = manifest['first_mutation_run_number']
    require(type(first) is int and first >= 1)
    relevant = [r for r in runs if r['run_number'] >= first
                and r['head_branch'] == manifest['runtime']['ref'].removeprefix('refs/heads/')
                and r['head_sha'] == manifest['runtime']['sha'] and r['id'] != current_id]
    # Conservative non-FIFO disposition: pending work blocks this invocation,
    # whose own before-writer receipt is harmless to the next invocation.
    require(all(r['status'] == 'completed' for r in relevant))
    require(len({r['id'] for r in relevant}) == len(relevant))
    histories = []
    consumed = set()
    for run in relevant:
        require(run['run_attempt'] == 1)
        identity = binding(manifest, run['id'], run['run_attempt'], run['head_sha'])
        history = records(read_log(run))
        receipts = [(kind, item) for kind, item in history if kind in ('PROOF6_PENDING', 'PROOF6_RESULT')]
        require(bool(receipts))  # cancellation/log loss is unknown, never assumed safe
        for kind, item in history:
            require(all(item.get(k) == v for k, v in identity.items()))
        consumptions = [item for kind, item in history if kind == 'PROOF6_CONSUMPTION']
        require(len(consumptions) <= 1)
        if consumptions:
            from proof_control import plan, OUTAGE
            fixed, digest = plan()
            entry = consumptions[0]
            op = entry.get('proof_operation')
            require(op in (*fixed['faults'], OUTAGE) and op not in consumed
                    and entry.get('proof_plan_sha256') == digest == manifest['proof_plan_sha256']
                    and entry.get('caller', {}).get('login') == fixed['caller']['login']
                    and entry.get('caller', {}).get('id') == fixed['caller']['id']
                    and run.get('actor', {}).get('id') == fixed['caller']['id']
                    and run.get('triggering_actor', {}).get('id') == fixed['caller']['id']
                    and entry.get('caller', {}).get('admin') is False
                    and entry.get('caller', {}).get('maintain') is False
                    and entry.get('result') == 'CONSUMED'
                    and entry.get('update_attempted') is False)
            expected_proposal = None if op == OUTAGE else hashlib.sha256(canonical(fixed['faults'][op]['proposal'])).hexdigest()
            require(entry.get('proposal_sha256') == expected_proposal)
            require(history.index(('PROOF6_CONSUMPTION', entry)) < history.index(receipts[0]))
            require(all(item.get('proof_operation') == op and item.get('proof_plan_sha256') == digest
                        for _, item in receipts))
            consumed.add(op)
        else:
            require(all(not item.get('proof_operation') for _, item in receipts))
        if last_operation := receipts[-1][1].get('proof_operation'):
            require(bool(consumptions) and last_operation == consumptions[0]['proof_operation'])
        attempted = [item for _, item in receipts if item.get('update_attempted') is True]
        last = receipts[-1][1]
        require(type(last.get('update_attempted')) is bool)
        if attempted:
            require(last['update_attempted'] is True)
            old, candidate = attempted[0]['old_sha'], attempted[0]['candidate_commit']
            disposition(old, candidate, old)  # validates exact distinct SHAs
            require(all(i['old_sha'] == old and i['candidate_commit'] == candidate for i in attempted))
            require(last.get('new_sha') in (None, candidate))
            if last['result'] == 'COMMITTED':
                require(receipts[-1][0] == 'PROOF6_RESULT' and last['new_sha'] == candidate
                        and last['remote_outcome'] == 'committed')
            else:
                require(last['result'] in ('INDETERMINATE', 'ERROR'))
        else:
            require(receipts[-1][0] == 'PROOF6_RESULT'
                    and last['result'] in ('BLOCKED', 'ERROR', 'REJECTED', 'APP_AUTH_SETUP_VERIFIED', 'OUTAGE_COMPLETED')
                    and last.get('new_sha') is None
                    and last['remote_outcome'] == 'not_attempted')
        histories.append((run, history, last))
    # Reconciliation records are emitted by this same pinned runtime, bound to
    # both the recording run and the exact target receipt. They survive a later
    # authority advance; never reinterpret an old ambiguity against a newer head.
    resolutions = [item for _, history, _ in histories for kind, item in history
                   if kind == 'PROOF6_RECONCILIATION']
    for run, _, last in histories:
        if not last['update_attempted'] or last['result'] == 'COMMITTED':
            continue
        matching = [r for r in resolutions if r.get('target_run_id') == run['id']]
        for r in matching:
            require(r['old_sha'] == last['old_sha'] and r['candidate_commit'] == last['candidate_commit'])
            expected = disposition(r['old_sha'], r['candidate_commit'], r['remote_sha'])
            require(r['read_only'] is True and r['result'] == expected['result']
                    and r['result'] in ('COMMITTED', 'NOT_COMMITTED'))
        require(len({r['result'] for r in matching}) <= 1)
        if not matching:
            observe({'phase': 'HELD_FOR_RECONCILIATION', 'target_run_id': run['id'],
                     'old_sha': last['old_sha'], 'candidate_commit': last['candidate_commit']})
            resolved = reconcile(last['old_sha'], last['candidate_commit'])
            expected = disposition(last['old_sha'], last['candidate_commit'], resolved['remote_sha'])
            require(resolved == expected and resolved['result'] in ('COMMITTED', 'NOT_COMMITTED'))
            emit(dict(resolved, target_run_id=run['id']))
    require(not requested_operation or requested_operation not in consumed)
    observe({'phase': 'ADMITTED', 'requested_operation': requested_operation})
