"""Fixed proof-only operations. No arbitrary fault or transport parameters."""
import hashlib
import json
from pathlib import Path

from writer import _canonical, _require, REPO

FAULTS = ('D02_PRE_SEND_STOP', 'D03_REMOTE_REJECTION', 'D07_DROP_PATCH_RESPONSE')
OUTAGE = 'D04_CONNECTIVITY_OUTAGE'
PLAN_PATH = Path(__file__).with_name('proof_plan.json')

def plan():
    raw = PLAN_PATH.read_bytes()
    value = json.loads(raw)
    from d03_rejection import POLICY
    from d04_capability import POLICY as D04_POLICY
    from d04_signal import POLICY as SIGNAL_POLICY
    _require(value['schema'] == 'PROOF6_R3I_PLAN_V1'
             and value['contract_commit'] == '2cb629820e3bd04e7c7edaa2b2364682e4dc5f1b'
             and set(value['faults']) == set(FAULTS)
             and value['caller'] == {'login': 'peaklinesoftware', 'id': 265169095}
             and value['max_consumptions_per_operation'] == 1
             and value['d03_boundary'] == POLICY
             and value['baseline'] == {'authority': 'fdf602669253e0a5d3c09f515d4dd41004db043e',
                 'state_sha256': 'd8e1a472f8060ece75d385a8bffa5f810c77065d01329409963ffb0a46406c5c', 'roadmap': 6}
             and value['infrastructure'] == {'operation': OUTAGE, 'case': 'D04',
                 'duration_seconds': 30, 'total_cap_seconds': 120, 'target': 'api.github.com',
                 'concurrency': 'proof6-authority-writer-r3'})
    expected_ids = {f'{group}{n:02}' for group, count in zip('ABCDEFGH', (9,12,11,9,6,14,3,8))
                    for n in range(1, count + 1)}
    rows = value['cases']
    _require(len(rows) == 72 and {r['id'] for r in rows} == expected_ids
             and all(r['disposition'] == 'FRESH' and r['method'] for r in rows)
             and sum(r['reason'] == 'FRESH_R3I' for r in rows) == 56
             and sum(r['reason'] == 'NO_VALID_PRIOR_EVIDENCE_SO_FRESH' for r in rows) == 16
             and value['accounting'] == {'FRESH_R3I':56, 'NO_VALID_PRIOR_EVIDENCE_SO_FRESH':16,
                                         'inherited':0, 'NOT_APPLICABLE':0, 'total':72}
             and value['workflow_budget'] == {'setup_bootstrap':1, 'ordinary':3, 'fault':4, 'recovery':2, 'total':10}
             and value['recovery']['completion_requests_in_R7'] == 2
             and value['recovery']['caller_selectors'] == [])
    groups = set(value['workflow_runs']) | set(value['external_evidence_groups'])
    _require(value['d04_signal'] == SIGNAL_POLICY and value['d04_capability'] == D04_POLICY
             and len(value['workflow_runs']) == value['workflow_budget']['total']
             and all(row['evidence_groups'] and set(row['evidence_groups']) <= groups for row in rows)
             and value['diagnostic_provenance']['acceptance_credit'] is False)
    return value, hashlib.sha256(raw).hexdigest()

def request(inputs):
    _require(type(inputs) is dict and set(inputs) <= {'proposal', 'proof_operation'})
    proposal, operation = inputs.get('proposal', ''), inputs.get('proof_operation', '')
    _require(type(proposal) is str and len(proposal.encode()) <= 65536 and type(operation) is str)
    value, digest = plan()
    if operation:
        _require(not proposal and operation in (*FAULTS, OUTAGE))
        proposal = '' if operation == OUTAGE else _canonical(value['faults'][operation]['proposal']).decode()
    return proposal, operation, value, digest

def qualify(env, get):
    value, _ = plan()
    caller = value['caller']
    _require(env['GITHUB_ACTOR'] == caller['login']
             and env['GITHUB_ACTOR_ID'] == str(caller['id'])
             and env['GITHUB_TRIGGERING_ACTOR'] == caller['login']
             and env['GITHUB_RUN_ATTEMPT'] == '1')
    return account_permission(get)

def account_permission(get):
    value, _ = plan()
    caller = value['caller']
    permission = get('repos/' + REPO + '/collaborators/' + caller['login'] + '/permission')
    _require(permission['user']['id'] == caller['id']
             and permission['user']['login'] == caller['login']
             and permission['permission'] == 'write' and permission['role_name'] == 'write')
    # role_name is GitHub's highest effective role; optional detailed flags must
    # agree if returned, but are not part of the endpoint's guaranteed schema.
    if 'permissions' in permission['user']:
        flags = permission['user']['permissions']
        _require(flags['push'] is True and flags['admin'] is False and flags['maintain'] is False)
    return {'login': caller['login'], 'id': caller['id'], 'permission': 'write',
            'admin': False, 'maintain': False,
            'environment_qualification': 'required separately in case evidence; not attested by account permission'}
