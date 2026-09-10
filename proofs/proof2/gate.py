"""Bounded pure Proof-2 candidate gate; no authoritative writes."""
import importlib.util
import json
from pathlib import Path
import re
import sys


# Load the accepted reducer by code-relative path, never from ambient cwd.
_spec = importlib.util.spec_from_file_location(
    '_accepted_proof1', Path(__file__).resolve().parent.parent / 'proof1' / 'replay.py')
proof1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(proof1)


def valid_id(value):
    return (type(value) is str and bool(value) and value == value.strip()
            and all(32 <= ord(c) <= 126 for c in value))


def valid_proposal(p):
    if type(p) is not dict or set(p) != {
            'proposal_id', 'project', 'subject', 'expected_state_sha256',
            'loop_id', 'expected_baton', 'action'}:
        return False
    return (all(valid_id(p[k]) for k in ('proposal_id', 'project', 'subject', 'loop_id'))
            and len(p['project'].split('/')) == 2
            and all(valid_id(part) for part in p['project'].split('/'))
            and type(p['expected_state_sha256']) is str
            and re.fullmatch('[0-9a-f]{64}', p['expected_state_sha256']) is not None
            and type(p['expected_baton']) is int and p['expected_baton'] >= 0
            and p['action'] == 'ADVANCE_ROADMAP')


def decide(history, proposal):
    """JSON-domain inputs -> canonicalizable decision, without changing inputs."""
    ident = proposal.get('proposal_id') if type(proposal) is dict else None
    result = {'decision': 'REJECT', 'proposal_id': ident if valid_id(ident) else None,
              'from_state_sha256': None, 'violations': []}
    violations = result['violations']
    try:
        current = proof1.reconstruct(history)
        result['from_state_sha256'] = current['state_sha256']
    except (ValueError, TypeError, KeyError, RecursionError):
        # Some malformed JSON-domain nested shapes raise Python schema errors.
        # They are rejected, never normalized or repaired.
        violations.append('INVALID_HISTORY')
    if not valid_proposal(proposal):
        violations.append('INVALID_PROPOSAL')
    if violations:
        return result

    state = current['state']
    event_id = 'proof2:proposal:' + proposal['proposal_id']
    checks = (
        (proposal['project'] != state['project'], 'WRONG_PROJECT'),
        (proposal['subject'] != state['subject'], 'WRONG_SUBJECT'),
        (proposal['expected_state_sha256'] != current['state_sha256'], 'STALE_STATE'),
        (proposal['loop_id'] != state['loop']['id'], 'WRONG_LOOP'),
        (proposal['expected_baton'] != state['loop']['baton'], 'WRONG_BATON'),
        (bool(state['holds']), 'ACTIVE_HOLD'),
        (bool(state['protected_work']), 'PROTECTED_WORK'),
        (state['child']['blocks_parent'], 'BLOCKING_CHILD'),
        (state['roadmap'] >= 11, 'NO_LEGAL_NEXT_ROADMAP'),
        (any(e['id'] == event_id for e in history['events']), 'REPLAYED_PROPOSAL'),
    )
    violations.extend(code for failed, code in checks if failed)
    if violations:
        return result

    event = {'id': event_id, 'seq': len(history['events']) + 1,
             'op': 'roadmap', 'data': {'position': state['roadmap'] + 1}}
    candidate = {'version': 1, 'events': history['events'] + [event]}
    predicted = proof1.reconstruct(candidate)
    return {'decision': 'ALLOW', 'proposal_id': proposal['proposal_id'],
            'from_state_sha256': current['state_sha256'], 'candidate_event': event,
            'candidate_state_sha256': predicted['state_sha256']}


def evaluate(raw):
    """Strict CLI transport; parsing failure carries no inferred identities."""
    try:
        envelope = json.loads(raw.decode('utf-8'), object_pairs_hook=proof1.unique_object,
                              parse_float=proof1.invalid_number,
                              parse_constant=proof1.invalid_number)
        proof1.fields(envelope, 'history proposal')
    except (ValueError, UnicodeError, RecursionError):
        return {'decision': 'REJECT', 'proposal_id': None,
                'from_state_sha256': None, 'violations': ['INVALID_PROPOSAL']}
    return decide(envelope['history'], envelope['proposal'])


if __name__ == '__main__':
    output = evaluate(sys.stdin.buffer.read())
    sys.stdout.buffer.write(proof1.canonical(output))
    sys.exit(0 if output['decision'] == 'ALLOW' else 2)
