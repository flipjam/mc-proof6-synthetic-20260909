"""Two fixed consumable operations and one fixed normal transition."""
from common import AREA, CAMPAIGN, _canonical, _digest, _require, parse

FAULTS = ('D03_REMOTE_REJECTION', 'D07_DROP_PATCH_RESPONSE')
AUTHORIZATIONS = dict(zip(FAULTS, ('P6WSV1-D03-01', 'P6WSV1-D07-01')))
AUTHORIZATIONS[''] = 'P6WSV1-POSTRECOVERY-01'
PROPOSALS = dict(zip((*FAULTS, ''), ('p6ws-v1-d03', 'p6ws-v1-d07', 'p6ws-v1-postrecovery')))
BUDGET = {'consumptions': 2, 'authority_patch_attempts': 3, 'authority_advances': 2,
          'journal_patch_attempts': 12, 'journal_advances': 11}
CALLER = {'login': 'peaklinesoftware', 'id': 265169095}


def plan():
    value = {'schema': 'P6WSV1_PLAN_V1', 'campaign': CAMPAIGN, 'faults': list(FAULTS),
             'authorizations': AUTHORIZATIONS, 'proposals': PROPOSALS, 'budget': BUDGET,
             'caller': CALLER, 'max_consumptions_per_operation': 1,
             'authority_attempts': [1, 1, 1], 'authority_advances': [0, 1, 1],
             'q0_consumptions': 0}
    return value, _digest(_canonical(value))


def authorization(operation):
    _require(type(operation) is str and operation in AUTHORIZATIONS)
    return AUTHORIZATIONS[operation]


def proposal_for(operation, manifest):
    authorization(operation)
    proposal = manifest['proposals'][operation]
    _require(proposal['proposal_id'] == PROPOSALS[operation])
    return proposal


def validate_payload(raw, operation, manifest):
    _require(type(raw) is bytes and len(raw) <= 65536)
    _require(raw == _canonical(proposal_for(operation, manifest)))


def request(inputs, manifest):
    # This is the only hosted request surface. No proposal or binding selectors.
    _require(type(inputs) is dict and set(inputs) == {'case'})
    case = inputs['case']
    _require(type(case) is str and case in (*FAULTS, 'POSTRECOVERY', 'RECOVER'))
    if case == 'RECOVER':
        return None, None
    operation = '' if case == 'POSTRECOVERY' else case
    return _canonical(proposal_for(operation, manifest)), operation


def account_permission(get):
    from common import REPO
    reply = get('repos/' + REPO + '/collaborators/' + CALLER['login'] + '/permission')
    _require(reply['user']['login'] == CALLER['login'] and type(reply['user']['id']) is int
             and reply['user']['id'] == CALLER['id'] and reply['role_name'] == reply['permission'] == 'write')
    if 'permissions' in reply['user']:
        flags = reply['user']['permissions']
        _require(flags['push'] is True and flags['admin'] is False and flags['maintain'] is False)
    return dict(**CALLER, permission='write', admin=False, maintain=False,
                environment_qualification='required separately in case evidence; not attested by account permission')
