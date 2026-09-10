"""Proof-1 offline reconstruction. Reads stdin once and writes only stdout."""
import hashlib
import json
import re
import sys


RULES = 'proof1-v1'


class InvalidHistory(ValueError):
    pass


def require(condition):
    if not condition:
        raise InvalidHistory()


def fields(obj, names):
    require(type(obj) is dict and set(obj) == set(names.split()))


def string(value):
    require(type(value) is str and bool(value) and value == value.strip()
            and all(32 <= ord(c) <= 126 for c in value))


def integer(value, minimum=0):
    require(type(value) is int and value >= minimum)


def repository(value):
    string(value)
    parts = value.split('/')
    require(len(parts) == 2)
    for part in parts:
        string(part)


def dependency(value):
    fields(value, 'repository revision sha')
    repository(value['repository'])
    integer(value['revision'], 1)
    require(type(value['sha']) is str
            and re.fullmatch('[0-9a-f]{40}', value['sha']) is not None)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def invalid_number(_):
    raise InvalidHistory()


def reconstruct(history):
    fields(history, 'version events')
    require(type(history['version']) is int and history['version'] == 1)
    events = history['events']
    require(type(events) is list and bool(events))
    ids = set()
    for event in events:
        fields(event, 'id seq op data')
        string(event['id'])
        require(event['id'] not in ids)
        ids.add(event['id'])
        integer(event['seq'], 1)
        string(event['op'])
        require(type(event['data']) is dict)
    events = sorted(events, key=lambda event: event['seq'])
    require([e['seq'] for e in events] == list(range(1, len(events) + 1)))
    require(events[0]['op'] == 'init')
    data = events[0]['data']
    fields(data, 'subject project roadmap dependency loop child')
    string(data['subject'])
    repository(data['project'])
    integer(data['roadmap'])
    require(data['roadmap'] == 0)
    dependency(data['dependency'])
    loop = data['loop']
    fields(loop, 'id baton owner')
    string(loop['id'])
    string(loop['owner'])
    integer(loop['baton'])
    child = data['child']
    fields(child, 'id parent status blocks_parent')
    string(child['id'])
    require(child['id'] != data['subject'] and child['parent'] == data['subject'])
    require(child['status'] in ('UNRESOLVED', 'BLOCKED'))
    require(type(child['blocks_parent']) is bool)
    # Copy nested records; never mutate the authoritative input while reducing.
    state = dict(data, dependency=dict(data['dependency']), loop=dict(loop),
                 child=dict(child))
    active = {'holds': set(), 'protected_work': set()}
    seen = {'holds': set(), 'protected_work': set()}
    for event in events[1:]:
        op, data = event['op'], event['data']
        if op in ('hold_add', 'hold_release', 'protect_add', 'protect_release'):
            fields(data, 'id')
            string(data['id'])
            key = 'holds' if op.startswith('hold_') else 'protected_work'
            ident = data['id']
            if op.endswith('_add'):
                require(ident not in seen[key])
                seen[key].add(ident)
                active[key].add(ident)
            else:
                require(ident in active[key])
                active[key].remove(ident)
        elif op == 'roadmap':
            fields(data, 'position')
            integer(data['position'])
            require(data['position'] == state['roadmap'] + 1
                    and data['position'] <= 11)
            state['roadmap'] = data['position']
        elif op == 'dependency':
            dependency(data)
            require(data['repository'] == state['dependency']['repository']
                    and data['revision'] == state['dependency']['revision'] + 1)
            state['dependency'] = dict(data)
        elif op == 'baton':
            fields(data, 'loop baton owner')
            string(data['owner'])
            integer(data['baton'])
            require(data['loop'] == state['loop']['id']
                    and data['baton'] == state['loop']['baton'] + 1)
            state['loop'] = {'id': data['loop'], 'baton': data['baton'],
                             'owner': data['owner']}
        elif op == 'child_disposition':
            fields(data, 'id status')
            require(data['id'] == state['child']['id']
                    and state['child']['status'] in ('UNRESOLVED', 'BLOCKED')
                    and data['status'] in ('RESOLVED', 'REJECTED'))
            state['child'] = dict(state['child'], status=data['status'],
                                  blocks_parent=False)
        else:
            raise InvalidHistory()
    state.update({key: sorted(value) for key, value in active.items()})
    return {'result': 'VALID', 'rules': RULES,
            'input_sha256': digest({'version': 1, 'events': events}),
            'state': state, 'state_sha256': digest({'rules': RULES, 'state': state})}


def replay(raw):
    """Pure bytes -> (exit code, canonical bytes), with no ambient authority."""
    try:
        history = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                             parse_float=invalid_number, parse_constant=invalid_number)
        return 0, canonical(reconstruct(history))
    except (ValueError, UnicodeError, RecursionError):
        return 2, canonical({'result': 'INVALID_HISTORY',
                             'input_sha256': hashlib.sha256(raw).hexdigest()})


if __name__ == '__main__':
    code, output = replay(sys.stdin.buffer.read())
    sys.stdout.buffer.write(output)
    sys.exit(code)
