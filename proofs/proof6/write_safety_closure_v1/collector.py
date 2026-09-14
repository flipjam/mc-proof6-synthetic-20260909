"""Independent GET-only proof collector; never imports writer or journal code."""
import base64
import hashlib
import types
import urllib.request
from common import (REPO, REPO_ID, REF, JOURNAL_REF, RUNTIME_REF, WORKFLOW, AREA,
                    _canonical, _digest, _require, _sha, parse)
from qualification import validate_manifest, qualify_q0, gate
from proof_control import FAULTS, AUTHORIZATIONS, BUDGET, CALLER, plan
import d03_rejection

SCHEMA = 'P6WSV1_JOURNAL_V1'
FIELDS = {'CONSUMED': {'binding'}, 'PENDING': {'binding', 'old', 'candidate', 'gate_sha256'},
          'SEND_ARMED': {'pending'}, 'TERMINAL': {'pending', 'disposition', 'observed', 'evidence', 'request_id', 'status', 'd03'}}


class ReadOnlyRemote:
    """No method/body/host argument and no redirect or ambient proxy."""
    def __init__(self, token):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise ValueError('REDIRECT_REFUSED')
        self.__http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.__token = token

    def get(self, suffix):
        _require(type(suffix) is str and suffix.startswith('/') and not suffix.startswith('//')
                 and '..' not in suffix and '#' not in suffix)
        request = urllib.request.Request('https://api.github.com/repos/' + REPO + suffix,
            method='GET', headers={'Accept': 'application/vnd.github+json',
                'Authorization': 'Bearer ' + self.__token, 'User-Agent': 'p6wsv1-independent-collector',
                'X-GitHub-Api-Version': '2022-11-28'})
        with self.__http.open(request, timeout=30) as response:
            raw = response.read(2_000_001)
        _require(len(raw) <= 2_000_000)
        return parse(raw)


class Inspection:
    def __init__(self, get):
        self.get = get
        self.accepted = gate()

    def ref(self, ref):
        _require(ref in (REF, JOURNAL_REF, RUNTIME_REF))
        value = self.get('/git/ref/' + ref.removeprefix('refs/'))
        _require(value['ref'] == ref and value['object']['type'] == 'commit')
        return _sha(value['object']['sha'])

    def blob(self, sha):
        value = self.get('/git/blobs/' + _sha(sha))
        _require(value['sha'] == sha and value['encoding'] == 'base64')
        raw = base64.b64decode(value['content'])
        _require(len(raw) <= 2_000_000 and hashlib.sha1(
            b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == sha)
        return raw

    def commit(self, sha):
        value = self.get('/git/commits/' + _sha(sha))
        _require(value['sha'] == sha)
        _sha(value['tree']['sha'])
        for parent in value['parents']:
            _sha(parent['sha'])
        return value

    def tree(self, sha):
        value = self.get('/git/trees/' + _sha(sha))
        _require(value['sha'] == sha and value['truncated'] is False)
        _require(len({e['path'] for e in value['tree']}) == len(value['tree']))
        return value['tree']

    def object(self, sha, path):
        commit = self.commit(sha)
        entries = self.tree(commit['tree']['sha'])
        _require(len(entries) == 1 and entries[0]['path'] == path
                 and entries[0]['type'] == 'blob' and entries[0]['mode'] == '100644')
        raw = self.blob(entries[0]['sha'])
        row = parse(raw)
        _require(raw == _canonical(row))
        return commit, row

    def source_blob(self, tree, path):
        pieces = path.split('/')
        for index, piece in enumerate(pieces):
            entries = [e for e in self.tree(tree) if e['path'] == piece]
            _require(len(entries) == 1)
            entry = entries[0]
            if index == len(pieces) - 1:
                _require(entry['type'] == 'blob' and entry['mode'] == '100644')
                return self.blob(entry['sha'])
            _require(entry['type'] == 'tree' and entry['mode'] == '040000')
            tree = entry['sha']

    def history(self, sha):
        commit, history = self.object(sha, 'history.json')
        return commit, history, self.accepted.proof1.reconstruct(history)

    def environment(self, name):
        from common import ENVIRONMENT
        _require(name == ENVIRONMENT)
        env = self.get('/environments/' + name)
        policies = self.get('/environments/' + name + '/deployment-branch-policies?per_page=100')
        _require(policies['total_count'] == 1 and len(policies['branch_policies']) == 1)
        reviews = [r for r in env['protection_rules'] if r['type'] == 'required_reviewers']
        _require(len(reviews) == 1)
        rule = reviews[0]
        _require(all(r['type'] == 'User' for r in rule['reviewers']))
        return {'name': env['name'], 'can_admins_bypass': env['can_admins_bypass'],
            'deployment_branch_policy': env['deployment_branch_policy'],
            'deployment_branches': [{k: p[k] for k in ('name', 'type')} for p in policies['branch_policies']],
            'prevent_self_review': rule['prevent_self_review'],
            'reviewer_ids': sorted(r['reviewer']['id'] for r in rule['reviewers'])}


def binding(m, b, operation):
    _require(set(b) == {'operation', 'authorization', 'run_id', 'run_attempt', 'runtime_sha',
        'manifest_sha256', 'build_sha256', 'plan_sha256', 'proposal_sha256', 'caller'})
    _require(b['operation'] == operation and b['authorization'] == AUTHORIZATIONS[operation]
             and type(b['run_id']) is int and b['run_id'] > 0
             and type(b['run_attempt']) is int and b['run_attempt'] == 1
             and b['runtime_sha'] == m['source_commit'] and b['manifest_sha256'] == _digest(_canonical(m))
             and b['build_sha256'] == m['build_sha256'] and b['plan_sha256'] == plan()[1]
             and b['proposal_sha256'] == _digest(_canonical(m['proposals'][operation])))
    _require(b['caller'] == dict(**CALLER, permission='write', admin=False, maintain=False,
        environment_qualification='required separately in case evidence; not attested by account permission')
        and b['caller']['admin'] is False and b['caller']['maintain'] is False and type(b['caller']['id']) is int)


def _inspect(m, evidence, get):
    validate_manifest(m, local=True)
    _require(type(evidence) is dict and set(evidence) == {'q0', 'authority_attempts', 'journal_attempts',
        'raw_process', 'sibling', 'writer_local_result'})
    qualify_q0(m, evidence['q0'])
    remote = Inspection(get)
    start = {ref: remote.ref(ref) for ref in (REF, JOURNAL_REF, RUNTIME_REF)}
    _require(start[RUNTIME_REF] == m['source_commit'])
    source = remote.commit(m['source_commit'])
    _require(source['tree']['sha'] == m['source_tree'])
    for path, digest in m['source_hashes'].items():
        _require(_digest(remote.source_blob(m['source_tree'], path)) == digest)
    _require(_digest(remote.source_blob(m['source_tree'], 'proofs/proof6/write_safety_closure_v1/build.json')) == m['build_sha256'])
    for expected in m['authority_rulesets'] + list(m['journal']['rulesets'].values()) + m['runtime_rulesets']:
        actual = get('/rulesets/' + str(expected['id']))
        # Full read-only collector evidence must include bypass actors.
        _require(actual == expected)
    _require(remote.environment(m['environment']) == m['environment_policy'])
    cursor, seen, reverse_rows = start[JOURNAL_REF], set(), []
    genesis = m['journal']['genesis_commit']
    while True:
        _require(cursor not in seen and len(seen) < 13)
        seen.add(cursor)
        commit, row = remote.object(cursor, 'operation.json')
        if cursor == genesis:
            _require(commit['parents'] == [] and commit['tree']['sha'] == m['journal']['genesis_tree']
                     and row == {'schema': SCHEMA, 'type': 'GENESIS', 'repository_id': REPO_ID, 'ref': JOURNAL_REF}
                     and _digest(_canonical(row)) == m['journal']['genesis_content_sha256'])
            break
        _require(len(commit['parents']) == 1)
        reverse_rows.append((cursor, commit['parents'][0]['sha'], row))
        cursor = commit['parents'][0]['sha']
    rows = list(reversed(reverse_rows))
    _require(len(rows) == BUDGET['journal_advances'])
    # Field order is part of the writer's frozen schema hash.
    schema_fields = {'CONSUMED': ['binding'], 'PENDING': ['binding', 'old', 'candidate', 'gate_sha256'],
        'SEND_ARMED': ['pending'], 'TERMINAL': ['pending', 'disposition', 'observed', 'evidence', 'request_id', 'status', 'd03']}
    _require(m['journal']['schema_sha256'] == _digest(_canonical({'schema': SCHEMA, 'fields': schema_fields})))
    baseline, history, state = remote.history(m['baseline_commit'])
    _require(history == m['baseline_history'] and state['state_sha256'] == m['baseline_state_sha256'])
    authority, index, operations = m['baseline_commit'], 0, []
    for operation in (*FAULTS, ''):
        if operation:
            _, _, consumed = rows[index]
            _require(consumed['type'] == 'CONSUMED')
            binding(m, consumed['binding'], operation)
            index += 1
        pending_sha, _, pending = rows[index]
        arm_sha, arm_parent, armed = rows[index + 1]
        terminal_sha, terminal_parent, terminal = rows[index + 2]
        for record, kind in ((pending, 'PENDING'), (armed, 'SEND_ARMED'), (terminal, 'TERMINAL')):
            _require(set(record) == {'schema', 'type'} | FIELDS[kind]
                     and record['type'] == kind and record['schema'] == SCHEMA)
        binding(m, pending['binding'], operation)
        if operation:
            _require(consumed == {'schema': SCHEMA, 'type': 'CONSUMED', 'binding': pending['binding']})
        _require(pending['old'] == authority and armed['pending'] == pending_sha
                 and arm_parent == pending_sha and terminal['pending'] == pending_sha and terminal_parent == arm_sha)
        _, old_history, _ = remote.history(authority)
        candidate_commit, candidate_history, _ = remote.history(pending['candidate'])
        decision = remote.accepted.decide(old_history, m['proposals'][operation])
        _require(decision['decision'] == 'ALLOW' and pending['gate_sha256'] == _digest(_canonical(decision))
                 and [p['sha'] for p in candidate_commit['parents']] == [authority]
                 and candidate_history == {'version': 1, 'events': old_history['events'] + [decision['candidate_event']]})
        if operation == FAULTS[0]:
            _require(terminal['disposition'] == 'NOT_COMMITTED' and terminal['evidence'] == 'FINAL_REJECTION'
                     and terminal['observed'] == authority and type(terminal['status']) is int and terminal['status'] == 403)
            pure = types.SimpleNamespace(pending={pending_sha: pending}, armed={pending_sha},
                                         rows=[(s, r) for s, _, r in rows])
            d03_rejection.validate(pure, pending_sha, terminal['d03'])
            _require(terminal['request_id'] == terminal['d03']['response']['request_id'])
        else:
            _require(terminal == {'schema': SCHEMA, 'type': 'TERMINAL', 'pending': pending_sha,
                'disposition': 'COMMITTED', 'observed': pending['candidate'], 'evidence': 'CANDIDATE_OBSERVED',
                'request_id': None, 'status': None, 'd03': None})
            authority = pending['candidate']
        operations.append((pending_sha, pending, arm_sha, terminal_sha, terminal))
        index += 3
    _require(index == len(rows) and authority == start[REF])
    sibling = evidence['sibling']
    _require(set(sibling) == {'winner', 'loser', 'parent'})
    _, d07, arm, winner, terminal = operations[1]
    _require(sibling['winner'] == winner and sibling['parent'] == arm
             and sibling['loser'] not in seen and sibling['loser'] != winner)
    losing_commit, losing_row = remote.object(sibling['loser'], 'operation.json')
    _require([p['sha'] for p in losing_commit['parents']] == [arm] and losing_row == terminal)
    attempts = evidence['authority_attempts']
    _require(type(attempts) is list and len(attempts) == 3)
    for attempt, operation, details in zip(attempts, (*FAULTS, ''), operations):
        pending_sha, pending, arm, _, _ = details
        _require(set(attempt) == {'authorization', 'pending', 'ref', 'candidate', 'force', 'transmitted', 'response', 'credential_source'}
                 and attempt['authorization'] == AUTHORIZATIONS[operation] and attempt['pending'] == pending_sha
                 and attempt['ref'] == REF and attempt['candidate'] == pending['candidate']
                 and attempt['force'] is False and attempt['transmitted'] is True
                 and attempt['response'] == {FAULTS[0]: '403_EXACT_REJECTION', FAULTS[1]: 'DROPPED', '': 'COMMITTED'}[operation]
                 and attempt['credential_source'] == (m['custody']['d03_credential_source'] if operation == FAULTS[0]
                                                        else m['custody']['writer_credential_source']))
    journal_attempts = evidence['journal_attempts']
    _require(type(journal_attempts) is list and len(journal_attempts) == 12)
    expected_attempts = [dict(parent=p, candidate=s, force=False, ref=JOURNAL_REF, advanced=True) for s, p, _ in rows]
    expected_attempts.insert(8, dict(parent=sibling['parent'], candidate=sibling['loser'], force=False, ref=JOURNAL_REF, advanced=False))
    _require(_canonical(journal_attempts) == _canonical(expected_attempts))
    process = parse(evidence['raw_process'].encode('ascii'))
    _require(set(process) == {'schema', 'manifest_sha256', 'source_commit', 'authority_attempts', 'journal_attempts',
        'original_results', 'd03_confirmation_loss', 'recovery_authority_attempts', 'reinvocations', 'process_exit_codes'}
        and process['schema'] == 'P6WSV1_SANITIZED_PROCESS_V1'
        and process['manifest_sha256'] == _digest(_canonical(m)) and process['source_commit'] == m['source_commit']
        and _canonical(process['authority_attempts']) == _canonical(attempts)
        and _canonical(process['journal_attempts']) == _canonical(journal_attempts)
        and process['original_results'] == ['INDETERMINATE', 'INDETERMINATE', 'COMMITTED']
        and process['d03_confirmation_loss'] == {'after_patch': True, 'before_first_confirmation': True, 'recovery_terminal_patches': 0}
        and type(process['recovery_authority_attempts']) is int and process['recovery_authority_attempts'] == 0
        and process['reinvocations'] == {'d03': 'REJECTED_BEFORE_PENDING', 'd07': 'REJECTED_BEFORE_PENDING',
            'proposal_replay': 'REJECTED_BEFORE_SEND', 'unknown_operation': 'REJECTED_BEFORE_MUTATION', 'stale_context': 'REJECTED_BEFORE_SEND'}
        and process['process_exit_codes'] == [0, 0, 0, 0, 0])
    _require({ref: remote.ref(ref) for ref in start} == start)
    return {'result': 'PASS', 'campaign': m['campaign'], 'authority': authority,
            'journal': start[JOURNAL_REF], 'budget': BUDGET, 'writer_local_result_used': False}


def collect(manifest, evidence, get):
    try:
        return _inspect(manifest, evidence, get)
    except (KeyError, TypeError, ValueError, IndexError, UnicodeError, RecursionError):
        return {'result': 'NOT_PASS', 'reason': 'MISSING_OR_CONTRADICTORY_EVIDENCE'}
    except Exception:
        return {'result': 'BLOCKED', 'reason': 'REMOTE_EVIDENCE_UNAVAILABLE'}
