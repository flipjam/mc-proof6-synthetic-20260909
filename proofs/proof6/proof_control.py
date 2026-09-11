"""Fixed proof-only operations. No arbitrary fault or transport parameters."""
import hashlib
import json
from pathlib import Path

from writer import _canonical, _require, REPO

FAULTS = ('D02_PRE_SEND_STOP', 'D03_REVOKE_CURRENT_TOKEN', 'D07_DROP_PATCH_RESPONSE')
OUTAGE = 'D04_CONNECTIVITY_OUTAGE'
PLAN_PATH = Path(__file__).with_name('proof_plan.json')

def plan():
    raw = PLAN_PATH.read_bytes()
    value = json.loads(raw)
    _require(value['schema'] == 'PROOF6_R3D_PLAN_V1'
             and value['contract_commit'] == 'c448ec30125943d9197139e028e9d992b25e8176'
             and set(value['faults']) == set(FAULTS)
             and value['caller'] == {'login': 'peaklinesoftware', 'id': 265169095}
             and value['max_consumptions_per_operation'] == 1
             and value['infrastructure'] == {'operation': OUTAGE, 'case': 'D04',
                 'duration_seconds': 120, 'target': 'api.github.com',
                 'concurrency': 'proof6-authority-writer-r3'})
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
