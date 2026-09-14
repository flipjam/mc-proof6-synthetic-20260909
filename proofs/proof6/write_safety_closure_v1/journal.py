"""One fixed Git safety journal. No public journal operation or Actions membership."""
import base64
import hashlib
import json
import re
import time

from journal_confirmation import _AppendEvidence

from writer import REPO, REPO_ID, APP_ID, _canonical, _digest, _require, _sha

REF = 'refs/heads/proof6-ws-closure-v1-journal'
PATH = 'operation.json'
SCHEMA = 'P6WSV1_JOURNAL_V1'
FIELDS = {
    'CONSUMED': ['binding'],
    'PENDING': ['binding', 'old', 'candidate', 'gate_sha256'],
    'SEND_ARMED': ['pending'],
    'TERMINAL': ['pending', 'disposition', 'observed', 'evidence', 'request_id', 'status', 'd03'],
}
SCHEMA_SHA256 = _digest(_canonical({'schema': SCHEMA, 'fields': FIELDS}))
GENESIS = {'schema': SCHEMA, 'type': 'GENESIS', 'repository_id': REPO_ID, 'ref': REF}
BASE = '/repos/' + REPO
FINAL_REJECTIONS = (400, 401, 403, 404, 409, 422)


def parse(raw):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            _require(k not in result)
            result[k] = v
        return result
    def invalid_number(value):
        raise ValueError('JOURNAL_NONINTEGER_NUMBER')
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_number,
                       parse_float=invalid_number)
    _require(raw == _canonical(value))
    return value


def hex64(value):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value))


def terminal_semantics(parent, row, pending, armed):
    """All record fields and exact protected lineage; no Git metadata excluded
    from the record. Commit author/time/message are outside this safety value.
    Schema/lifecycle/evidence validity is separately mandatory before comparison.
    """
    _sha(parent)
    _require(type(row) is dict and row.get('type') == 'TERMINAL'
             and set(row) == {'schema', 'type', *FIELDS['TERMINAL']}
             and row['schema'] == SCHEMA)
    return _canonical(dict(parent=parent, terminal=row, operation=pending,
                           send_armed=armed))


class Journal:
    _completion_label = 'ordinary'
    def __init__(self, writer):
        self.writer = writer
        self.m = writer._manifest
        _require(self.m is not None)
        self.config = self.m['journal']
        c = self.config
        _require(set(c) == {'ref', 'path', 'genesis_commit', 'genesis_tree',
                           'genesis_content_sha256', 'schema_sha256', 'rulesets'})
        _require(c['ref'] == REF and c['path'] == PATH
                 and c['schema_sha256'] == SCHEMA_SHA256
                 and c['genesis_content_sha256'] == _digest(_canonical(GENESIS)))
        _sha(c['genesis_commit']); _sha(c['genesis_tree'])
        self.check_protection()
        self.head = None
        self.rows = []
        self.used = set()
        self.pending = {}
        self.armed = set()
        self.resolved = set()
        self._permit = None
        self.read()

    def call(self, method, suffix, body=None):
        return self.writer._call(self.writer._installation_token, method, BASE + suffix, body)

    def check_protection(self):
        from ruleset_view import visible
        rules = self.config['rulesets']
        _require(set(rules) == {'integrity', 'update'})
        for kind, types in [('integrity', ['creation', 'deletion', 'non_fast_forward']),
                            ('update', ['update'])]:
            expected = rules[kind]
            _require(type(expected['id']) is int and expected['id'] > 0
                     and expected['target'] == 'branch' and expected['enforcement'] == 'active'
                     and expected['source'] == REPO and expected['source_type'] == 'Repository'
                     and expected['conditions'] == {'ref_name': {'include': [REF], 'exclude': []}}
                     and expected['rules'] == [{'type': t} for t in types])
            actual = self.call('GET', '/rulesets/' + str(expected['id']))
            _require(visible(actual) == visible(expected))
            # App-token API may omit bypass actors. Frozen setup must independently
            # verify the full configuration; when visible, require the exact list.
            if 'bypass_actors' in actual:
                allowed = [] if kind == 'integrity' else [
                    {'actor_id': APP_ID, 'actor_type': 'Integration', 'bypass_mode': 'always'}]
                _require(actual['bypass_actors'] == allowed)

    def remote(self):
        ref = self.call('GET', '/git/ref/' + REF.removeprefix('refs/'))
        _require(ref['ref'] == REF and ref['object']['type'] == 'commit')
        return _sha(ref['object']['sha'])

    def read(self, _expected_head=None, _expected_parent=None):
        head = cursor = self.remote()
        if _expected_head is not None:
            evidence = self._append_evidence
            evidence.value['reconstruction_entry_head'] = head
            evidence.require(head == _expected_head, 'RECONSTRUCTION_ENTRY_MISMATCH')
        rows, seen = [], set()
        while True:
            _require(cursor not in seen and len(seen) < 5000)
            seen.add(cursor)
            commit = self.call('GET', '/git/commits/' + cursor)
            _require(commit['sha'] == cursor)
            if _expected_head is not None and cursor == _expected_head:
                evidence.require(len(commit['parents']) == 1 and commit['parents'][0]['sha'] == _expected_parent,
                                 'RECONSTRUCTION_PARENT_MISMATCH')
            tree_sha = _sha(commit['tree']['sha'])
            tree = self.call('GET', '/git/trees/' + tree_sha)
            _require(tree['sha'] == tree_sha and tree['truncated'] is False and len(tree['tree']) == 1)
            entry = tree['tree'][0]
            _require(entry['path'] == PATH and entry['mode'] == '100644' and entry['type'] == 'blob')
            blob_sha = _sha(entry['sha'])
            blob = self.call('GET', '/git/blobs/' + blob_sha)
            _require(blob['sha'] == blob_sha and blob['encoding'] == 'base64')
            raw = base64.b64decode(blob['content'])
            _require(len(raw) <= 16384 and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == blob_sha)
            row = parse(raw)
            if cursor == self.config['genesis_commit']:
                _require(row == GENESIS and tree_sha == self.config['genesis_tree'] and commit['parents'] == [])
                break
            _require(len(commit['parents']) == 1)
            rows.append((cursor, row))
            cursor = _sha(commit['parents'][0]['sha'])
        self.validate(list(reversed(rows)))
        final_head = self.remote()
        if _expected_head is not None:
            evidence.value['reconstruction_final_head'] = final_head
            evidence.require(final_head == head == _expected_head, 'RECONSTRUCTION_FINAL_MISMATCH')
        _require(final_head == head)
        self.head, self.rows = head, list(reversed(rows))
        return self

    def check_binding(self, b):
        from proof_control import plan, authorization, proposal_for
        fixed, digest = plan()
        _require(set(b) == {'operation', 'run_id', 'run_attempt', 'runtime_sha', 'manifest_sha256',
                           'build_sha256', 'plan_sha256', 'proposal_sha256', 'caller', 'authorization'})
        _require(type(b['operation']) is str and b['operation'] in ('', *fixed['faults'])
                 and type(b['run_id']) is int and b['run_id'] > 0
                 and type(b['run_attempt']) is int and b['run_attempt'] == 1
                 and b['runtime_sha'] == self.m['runtime']['sha']
                 and b['manifest_sha256'] == self.writer._manifest_digest
                 and b['build_sha256'] == self.m['build_sha256']
                 and b['plan_sha256'] == digest == self.m['proof_plan_sha256'])
        caller = b['caller']
        _require(type(caller) is dict and type(caller.get('id')) is int
                 and caller.get('admin') is False and caller.get('maintain') is False)
        _require(caller == {'login': fixed['caller']['login'], 'id': fixed['caller']['id'],
                            'permission': 'write', 'admin': False, 'maintain': False,
                            'environment_qualification': 'required separately in case evidence; not attested by account permission'})
        hex64(b['proposal_sha256'])
        _require(b['authorization'] == authorization(b['operation']))
        payload = proposal_for(b['operation'], self.m)
        _require(b['proposal_sha256'] == _digest(_canonical(payload)))

    def validate(self, rows):
        used, claims, pending, armed, resolved = set(), {}, {}, set(), set()
        ids = set()
        previous = self.config['genesis_commit']
        arms, terminals = {}, {}
        for sha, r in rows:
            kind = r.get('type')
            _require(kind in FIELDS and set(r) == {'schema', 'type', *FIELDS[kind]} and r['schema'] == SCHEMA)
            if kind in ('CONSUMED', 'PENDING'):
                b = r['binding']; self.check_binding(b)
                opid = _digest(_canonical(b))
            if kind == 'CONSUMED':
                _require(b['operation'] and b['operation'] not in used)
                # All prior sends must be resolved before reserving new behavior.
                _require(set(pending) <= resolved)
                _require((b['operation'] == 'D03_REMOTE_REJECTION' and not used and not pending)
                         or (b['operation'] == 'D07_DROP_PATCH_RESPONSE'
                             and used == {'D03_REMOTE_REJECTION'} and len(resolved) == 1))
                used.add(b['operation']); claims[opid] = b
            elif kind == 'PENDING':
                _sha(r['old']); _sha(r['candidate']); hex64(r['gate_sha256'])
                _require(r['old'] != r['candidate'] and opid not in ids
                         and r['candidate'] not in {p['candidate'] for p in pending.values()}
                         and set(pending) <= resolved)
                if b['operation']:
                    _require(claims.get(opid) == b)
                if not b['operation']:
                    _require(used == {'D03_REMOTE_REJECTION', 'D07_DROP_PATCH_RESPONSE'}
                             and len(pending) == len(resolved) == 2
                             and all(p['binding']['operation'] for p in pending.values())
                             and any(pending[t]['binding']['operation'] == 'D07_DROP_PATCH_RESPONSE'
                                     and terminals[t][2]['disposition'] == 'COMMITTED' for t in terminals))
                ids.add(opid); pending[sha] = r
            elif kind == 'SEND_ARMED':
                target = r['pending']
                _require(target == previous and target in pending and target not in armed and target not in resolved)
                armed.add(target)
                arms[target] = sha
            else:
                target = r['pending']
                _require(target in pending and target not in resolved)
                p = pending[target]; _sha(r['observed'])
                _require(previous == arms.get(target, target))
                evidence = r['evidence']
                is_d03_rejection = p['binding']['operation'] == 'D03_REMOTE_REJECTION' and evidence == 'FINAL_REJECTION'
                if is_d03_rejection:
                    # Revalidate exact protected receipt on EVERY complete replay.
                    from d03_rejection import validate
                    self.pending, self.armed, self.rows = pending, armed, rows
                    validate(self, target, r['d03'])
                    _require(r['status'] == 403 and type(r['status']) is int
                             and r['request_id'] == r['d03']['response']['request_id'])
                else:
                    _require(r['d03'] is None)
                if evidence == 'UNARMED':
                    _require(target not in armed and r['observed'] == p['old']
                             and r['disposition'] == 'NOT_COMMITTED' and r['status'] is None and r['request_id'] is None)
                elif evidence == 'CANDIDATE_OBSERVED':
                    _require(target in armed and r['observed'] == p['candidate']
                             and r['disposition'] == 'COMMITTED' and r['status'] is None and r['request_id'] is None)
                else:
                    _require(evidence == 'FINAL_REJECTION' and target in armed
                             and r['observed'] == p['old'] and r['disposition'] == 'NOT_COMMITTED'
                             and type(r['status']) is int and r['status'] in FINAL_REJECTIONS
                             and ((is_d03_rejection and r['request_id'] is None) or
                                  (type(r['request_id']) is str and re.fullmatch('[A-Za-z0-9:-]{1,128}', r['request_id']))))
                resolved.add(target)
                terminals[target] = (sha, previous, r)
            previous = sha
        self.used, self.pending, self.armed, self.resolved = used, pending, armed, resolved
        self.arms, self.terminals = arms, terminals

    def append(self, kind, **fields):
        row = dict(schema=SCHEMA, type=kind, **fields)
        parent = self.head
        evidence = self._append_evidence = _AppendEvidence(self.writer, kind, parent, _digest(_canonical(row)))
        try:
            return self._append_once(kind, row, parent, evidence)
        except BaseException:
            # Diagnostic failure must never turn into admission or a send permit.
            # Every possible mutation remains unconfirmed until canonical proof.
            if not evidence.failed:
                evidence.emit('FINAL', evidence.reason, 'BLOCKED')
            raise

    def _append_once(self, kind, row, parent, evidence):
        # Validate proposed lifecycle before creating even non-authoritative objects.
        evidence.at('VALIDATION', 'VALIDATION_FAILED')
        self.validate(self.rows + [('f' * 40, row)])
        evidence.at('PROTECTION', 'PROTECTION_FAILED')
        self.check_protection()
        evidence.at('PARENT_CHECK', 'PARENT_CHANGED')
        _require(self.remote() == parent)
        evidence.at('OBJECT_CREATION', 'OBJECT_CREATION_FAILED')
        blob = self.call('POST', '/git/blobs', {'content': base64.b64encode(_canonical(row)).decode(), 'encoding': 'base64'})
        tree = self.call('POST', '/git/trees', {'tree': [{'path': PATH, 'type': 'blob', 'mode': '100644', 'sha': _sha(blob['sha'])}]})
        child = self.call('POST', '/git/commits', {'message': 'Proof6 safety ' + _digest(_canonical(row)),
                                                'tree': _sha(tree['sha']), 'parents': [parent]})
        child_sha = _sha(child['sha'])
        evidence.value['candidate'] = child_sha
        evidence.at('CANDIDATE_CHECK', 'CANDIDATE_INVALID')
        _require(child_sha != parent and self.remote() == parent)
        evidence.value['patch_entered'] = True
        evidence.at('PATCH_ENTERED', 'PATCH_UNCONFIRMED')
        self.writer._journal_append_observer = evidence
        try:
            result = self.call('PATCH', '/git/refs/' + REF.removeprefix('refs/'), {'sha': child_sha, 'force': False})
        except Exception:
            # One request only. The exact child must be the current remote head;
            # old/sibling/descendant/unreadable stays blocked, never a retry.
            evidence.value['patch_call'] = 'EXCEPTION'
        else:
            evidence.value['patch_call'] = 'RETURNED'
            if (kind == 'TERMINAL' and row['evidence'] == 'FINAL_REJECTION'
                    and self.pending[row['pending']]['binding']['operation'] == 'D03_REMOTE_REJECTION'):
                _require(result['ref'] == REF and result['object']['sha'] == child_sha)
                # Fixed P6WSV1 D03 subcondition: successful journal PATCH boundary,
                # BEFORE the first canonical confirmation read. Never a retry.
                evidence.at('D03_LOSS', 'D03_CONFIRMATION_LOST')
                raise ValueError('P6WSV1_D03_TERMINAL_CONFIRMATION_LOST')
        finally:
            self.writer._journal_append_observer = None
        evidence.at('PATCH_RESULT', 'PATCH_UNCONFIRMED')
        return self._confirm_append(parent, child_sha, row, evidence)

    def _confirm_append(self, parent, child_sha, row, evidence):
        # Only exact P permits a further read. Never retry an error or mutation.
        for observation in range(3):
            evidence.at('REF_OBSERVATION', 'REF_OBSERVATION_FAILED')
            head = self.remote()
            evidence.value['observed_heads'].append(head)
            evidence.emit('REF_OBSERVATION')
            if head == child_sha:
                break
            evidence.require(head == parent, 'CONFLICTING_HEAD')
            evidence.require(observation < 2, 'PARENT_UNCONFIRMED')
            evidence.at('OLD_PARENT_WAIT', 'WAIT_FAILED')
            time.sleep(1)
        evidence.at('RECONSTRUCTION', 'RECONSTRUCTION_FAILED')
        self.read(_expected_head=child_sha, _expected_parent=parent)
        evidence.require(self.head == child_sha and self.rows[-1] == (child_sha, row), 'RECORD_MISMATCH')
        evidence.emit('FINAL', 'EXACT_APPEND', 'CONFIRMED')
        return child_sha

    def operation_binding(self, proposal, operation):
        b = self.writer._receipt_binding
        result = {'operation': operation, 'run_id': b['run_id'], 'run_attempt': b['run_attempt'],
                  'runtime_sha': b['runtime_sha'], 'manifest_sha256': self.writer._manifest_digest,
                  'build_sha256': self.m['build_sha256'], 'plan_sha256': self.m['proof_plan_sha256'],
                  'proposal_sha256': _digest(proposal), 'caller': b['caller'],
                  'authorization': __import__('proof_control').authorization(operation)}
        self.check_binding(result)
        return result

    def consume(self, binding):
        return self.append('CONSUMED', binding=binding)

    def begin(self, binding, old, candidate, gate):
        return self.append('PENDING', binding=binding, old=old, candidate=candidate, gate_sha256=_digest(_canonical(gate)))

    def arm(self, pending):
        _require(pending in self.pending)
        owner = self.pending[pending]['binding']
        _require(owner['run_id'] == self.writer._receipt_binding['run_id']
                 and owner['run_attempt'] == self.writer._receipt_binding['run_attempt'])
        child = self.append('SEND_ARMED', pending=pending)
        self._permit = (pending, child)

    def take_send(self, candidate):
        permit, self._permit = self._permit, None
        _require(permit is not None)
        pending, head = permit
        _require(self.remote() == head and pending in self.armed and pending not in self.resolved
                 and self.pending[pending]['candidate'] == candidate)
        # In-memory permit is consumed before transport; even repeated calls on
        # this object cannot resend. Recovery never creates a permit.

    def finish(self, pending, observed, evidence, status=None, request_id=None, d03=None):
        p = self.pending[pending]
        disposition = 'COMMITTED' if evidence == 'CANDIDATE_OBSERVED' else 'NOT_COMMITTED'
        return self.append('TERMINAL', pending=pending, disposition=disposition,
                           observed=observed, evidence=evidence, status=status, request_id=request_id, d03=d03)

    def reconcile(self, current):
        """Complete ordered dispositions, exact gate-produced authority chain.
        No gate output is retained for mutation and no send permit is created.
        """
        self.read()
        expected = self.m['baseline_commit']
        self.writer._history(self.m['baseline_commit'])
        unresolved = None
        for pending, row in self.pending.items():
            _require(unresolved is None and row['old'] == expected)
            self.writer._validate_transition(row)
            if pending in self.terminals:
                terminal = self.terminals[pending][2]
                if terminal['disposition'] == 'COMMITTED':
                    expected = row['candidate']
            else:
                unresolved = pending
        remote = current()
        if unresolved is None:
            _require(remote == expected)
        else:
            row = self.pending[unresolved]
            # Only affirmative candidate observation permits missing-terminal
            # completion. Old alone never resolves an armed or unarmed record.
            _require(unresolved in self.arms and self.head == self.arms[unresolved]
                     and remote == row['candidate'])
            expected = remote
        _require(self.remote() == self.head and current() == expected)
        return expected, unresolved

    def _completion_boundary(self):
        """Fixed internal transport boundary; production recovery does nothing."""

    def recover(self, current, observe=lambda item: None):
        # One method invocation, one possible completion PATCH. No loop/retry.
        expected, pending = self.reconcile(current)
        if pending is not None:
            observe({'phase': 'HELD_FOR_RECONCILIATION', 'pending': pending})
            parent = self.head
            p = self.pending[pending]
            row = dict(schema=SCHEMA, type='TERMINAL', pending=pending,
                       disposition='COMMITTED', observed=p['candidate'],
                       evidence='CANDIDATE_OBSERVED', status=None, request_id=None, d03=None)
            normative = terminal_semantics(parent, row, p, self.arms[pending])
            self.validate(self.rows + [('f' * 40, row)])
            blob = self.call('POST', '/git/blobs', {'content': base64.b64encode(_canonical(row)).decode(), 'encoding': 'base64'})
            tree = self.call('POST', '/git/trees', {'tree': [{'path': PATH, 'type': 'blob', 'mode': '100644', 'sha': _sha(blob['sha'])}]})
            # Distinct invocation provenance is nonsafety commit message only.
            child = self.call('POST', '/git/commits', {
                'message': 'Proof6 terminal completion ' + self._completion_label + ' ' + str(self.writer._receipt_binding['run_id']),
                'tree': _sha(tree['sha']), 'parents': [parent]})
            candidate = _sha(child['sha'])
            self.check_protection()
            self.writer._runtime_guard(self.m)
            self.writer._enforcement(self.writer._installation_token)
            checked, missing = self.reconcile(current)
            _require(self.head == parent and missing == pending and checked == expected)
            # A request admitted here may arrive after another valid sibling.
            # The only proof hook is in the frozen recovery-only entry.
            self._completion_boundary()
            if self.writer._last_evidence is not None:
                self.writer._last_evidence.update(result='INDETERMINATE',
                    journal_completion_attempted=True, admission='BLOCKED',
                    historical_invocation_reclassified=False)
            try:
                self.call('PATCH', '/git/refs/' + REF.removeprefix('refs/'), {'sha': candidate, 'force': False})
            except Exception:
                pass
            # Every outcome requires complete canonical replay. Neither a 2xx,
            # orphan object nor this invocation's candidate SHA grants membership.
            confirmed, missing = self.reconcile(current)
            _require(missing is None)
            winner, winner_parent, terminal = self.terminals[pending]
            _require(terminal_semantics(winner_parent, terminal, self.pending[pending],
                                       self.arms[pending]) == normative)
            # Later fully explained gated advances do not erase this terminal's
            # canonical membership. reconcile already proved that continuity.
            expected = confirmed
            observe({'phase': 'TERMINAL_COMPLETION_CONFIRMED', 'pending': pending,
                     'invocation': self._completion_label,
                     'candidate': candidate, 'canonical_terminal': winner,
                     'candidate_canonical': candidate == winner})
        for original, (terminal, parent, row) in self.terminals.items():
            observe({'phase': 'CANONICAL_DISPOSITION_CONFIRMED', 'pending': original,
                     'terminal': terminal, 'terminal_parent': parent, 'journal_head': self.head,
                     'authority': expected, 'evidence_class': row['evidence'],
                     'safety_sha256': _digest(terminal_semantics(parent, row,
                         self.pending[original], self.arms.get(original))),
                     'original_binding': self.pending[original]['binding'],
                     'recovery_binding': self.writer._receipt_binding})
        observe({'phase': 'ADMITTED', 'journal_head': self.head})
        return expected
