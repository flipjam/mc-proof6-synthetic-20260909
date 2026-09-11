"""R3e exact remote permission rejection; no revocation or log recovery."""
import json
import re
from writer import REPO, REF, _canonical, _digest, _require
import d03_job_token

OPERATION = 'D03_REMOTE_REJECTION'
BODY_LIMIT = 4096
MESSAGE = 'Resource not accessible by integration'
URL = 'https://api.github.com/repos/' + REPO + '/git/refs/heads/proof6-authority'
POLICY = {'credential_source': d03_job_token.SOURCE,
          'effective_permissions': d03_job_token.PERMISSIONS,
          'response_schema': 'PROOF6_R3E_PERMISSION_REJECTION_V1',
          'body_limit': BODY_LIMIT, 'status': 403, 'message': MESSAGE}


def body(raw):
    _require(type(raw) is bytes and len(raw) <= BODY_LIMIT)
    def unique(pairs):
        result = {}
        for k, v in pairs:
            _require(k not in result)
            result[k] = v
        return result
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    _require(type(value) is dict and set(value) <= {'message', 'documentation_url', 'status'}
             and value.get('message') == MESSAGE)
    if 'status' in value:
        _require(type(value['status']) is str and value['status'] == '403')
    if 'documentation_url' in value:
        _require(value['documentation_url'] == 'https://docs.github.com/rest/git/refs#update-a-reference')
    return value


def expected(journal, pending):
    p = journal.pending[pending]
    b = p['binding']
    _require(b['operation'] == OPERATION and pending in journal.armed)
    arms = [sha for sha, row in journal.rows if row['type'] == 'SEND_ARMED' and row['pending'] == pending]
    _require(len(arms) == 1)
    return dict(schema=POLICY['response_schema'], binding=b, pending=pending, send_armed=arms[0],
                gate_sha256=p['gate_sha256'], old=p['old'], candidate=p['candidate'],
                endpoint=URL, method='PATCH', ref=REF, payload={'sha': p['candidate'], 'force': False})


def receipt(journal, pending, transport):
    result = expected(journal, pending)
    result.update(credential=transport['d03_credential'], response=transport['d03_response'],
                  enforcement_unchanged=transport['d03_enforcement_unchanged'])
    validate(journal, pending, result)
    return result


def validate(journal, pending, receipt):
    fixed = expected(journal, pending)
    _require(set(receipt) == set(fixed) | {'credential', 'response', 'enforcement_unchanged'})
    _require(_canonical({k: receipt[k] for k in fixed}) == _canonical(fixed))
    d03_job_token.validate(receipt['credential'], fixed['binding'])
    _require(receipt['enforcement_unchanged'] is True)
    r = receipt['response']
    _require(set(r) == {'transmitted', 'consumed', 'status', 'request_id', 'body',
                        'body_sha256', 'rate_limit_remaining', 'retry_after'})
    _require(r['transmitted'] is True and r['consumed'] is True
             and type(r['status']) is int and r['status'] == 403
             and r['retry_after'] is None
             and (r['rate_limit_remaining'] is None or
                  (type(r['rate_limit_remaining']) is str and
                   re.fullmatch('[0-9]+', r['rate_limit_remaining']) and int(r['rate_limit_remaining']) > 0)))
    _require(r['request_id'] is None or (type(r['request_id']) is str
             and re.fullmatch('[A-Za-z0-9:-]{1,128}', r['request_id'])))
    raw = r['body'].encode('utf-8')
    body(raw)
    _require(_digest(raw) == r['body_sha256'])
