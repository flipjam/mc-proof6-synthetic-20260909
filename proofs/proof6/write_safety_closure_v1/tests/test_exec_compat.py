"""Prospective qualification and launcher/collector tests; sockets prohibited."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import unittest
from unittest.mock import patch
import exec_compat_fixtures as x
from exec_compat_fixtures import f, q
from common import *
from common import _canonical, _digest, parse
import collector
import launcher


class ExecCompat(unittest.TestCase):
    def setUp(self):
        self.network = patch.object(socket, 'socket', side_effect=AssertionError('OFFLINE_ONLY'))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.g, self.m = x.setup()

    def reject(self, mutate, *, reseal=True):
        m = copy.deepcopy(self.m)
        mutate(m)
        if reseal:
            x.seal_configuration(m)
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
            q.validate_exec_manifest(m, local=True)

    def test_exact_semantic_object_and_independent_digest(self):
        # Independent serialization, including order/whitespace invariance.
        a = self.m['compatibility_admission']
        raw = json.dumps(dict(reversed(list(a.items()))), indent=2)
        semantic = json.loads(raw)
        canonical = json.dumps(semantic, ensure_ascii=True, sort_keys=True,
                               separators=(',', ':'), allow_nan=False).encode('utf-8')
        required = '41459434594cd31bfe12f7c0ca0594d5378f25a3d3a3c36e1661e07f9ffcd9a4'
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), required)
        self.assertEqual(q.qualify_exec_compat(semantic, required)['result'], 'EXEC_COMPAT_QUALIFIED')
        self.assertIs(q.validate_exec_manifest(self.m, local=True), self.m)
        self.assertIs(q.validate_manifest(self.m, local=True), self.m)

    def test_every_admission_field_changed_missing_or_wrong_type(self):
        for key, value in self.m['compatibility_admission'].items():
            for replacement in (value + '-WRONG', None, True, 1, {}, []):
                with self.subTest(key=key, replacement=replacement):
                    self.reject(lambda m: m['compatibility_admission'].update({key: replacement}))
            with self.subTest(missing=key):
                self.reject(lambda m: m['compatibility_admission'].pop(key))
        self.reject(lambda m: m['compatibility_admission'].update(extra='PASS'))

    def test_historical_q0_pass_and_cross_campaign_pass_rejected_even_rehashed(self):
        for key, values in {
            'historical_q0_disposition': ['PASS', 'PASSED', 'Q0_QUALIFIED', 'PASS_Q0_COMPAT_REVIEW_V1'],
            'campaign': ['P6-OTHER', 'P6-R3k'],
            'compatibility_result': ['PASS', 'FAIL', 'NOT_PASS_Q0_COMPAT_REVIEW_V1'],
        }.items():
            for value in values:
                def mutate(m):
                    m['compatibility_admission'][key] = value
                    m['compatibility_admission_sha256'] = _digest(_canonical(m['compatibility_admission']))
                with self.subTest(key=key, value=value):
                    self.reject(mutate)

    def test_wrong_digest_and_strict_json(self):
        for digest in ('0'*64, None, True, '', q.EXEC_COMPAT_ADMISSION_SHA256.upper()):
            self.reject(lambda m: m.update(compatibility_admission_sha256=digest))
        for raw in ('{"schema":1,"schema":2}', '{"value":NaN}', '{"value":Infinity}',
                    '{"value":-Infinity}', '{"value":1.5}', '{}{}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse(raw)

    def test_manifest_identity_and_source_hashes(self):
        for key, value in {
            'schema': 'P6WSV1_MANIFEST_V1', 'successor_contract': 'OTHER', 'campaign': 'OTHER',
            'source_identity': 'OTHER', 'accepted_source_commit': '0'*40,
            'accepted_source_tree': '0'*40, 'source_commit': ACCEPTED_SOURCE,
            'source_tree': ACCEPTED_TREE, 'build_sha256': '0'*64,
            'workflow_identity': 'OTHER', 'workflow_ref': REPO+'/'+WORKFLOW+'@'+RUNTIME_REF,
            'workflow_sha256': '0'*64, 'frozen': False, 'repository': 'other/repo',
            'environment': 'other', 'concurrency': 'other', 'ref': RUNTIME_REF,
            'source_base': '0'*40, 'baseline_state_sha256': '0'*64,
        }.items():
            with self.subTest(key=key):
                self.reject(lambda m: m.update({key: value}))
        for key, value in {'ref': RUNTIME_REF, 'sha': '0'*40, 'tree': '0'*40,
                           'workflow': '.github/workflows/other.yml'}.items():
            with self.subTest(runtime=key):
                self.reject(lambda m: m['runtime'].update({key: value}))
        self.reject(lambda m: m['source_hashes'].update({WORKFLOW: '0'*64}))
        self.reject(lambda m: m.update(q0_evidence_sha256='0'*64))

    def test_missing_duplicate_invalid_ruleset_ids(self):
        self.reject(lambda m: m.pop('runtime_rulesets'), reseal=False)
        self.reject(lambda m: m.update(runtime_rulesets=[]))
        for index in (0, 1):
            self.reject(lambda m: m['runtime_rulesets'][index].pop('id'))
            self.reject(lambda m: m['runtime_rulesets'].pop(index))
            for value in (None, True, False, 0, -1, 1.0, '1101', {}, []):
                with self.subTest(index=index, value=value):
                    self.reject(lambda m: m['runtime_rulesets'][index].update(id=value))
        for other in (self.m['runtime_rulesets'][0]['id'], self.m['authority_rulesets'][0]['id'],
                      self.m['journal']['rulesets']['integrity']['id']):
            self.reject(lambda m: m['runtime_rulesets'][1].update(id=other))

    def test_ruleset_and_environment_no_bypass(self):
        for index in (0, 1):
            for key, value in {'enforcement': 'evaluate', 'source': 'other/repo',
                'bypass_actors': [{'actor_id': APP_ID, 'actor_type': 'Integration', 'bypass_mode': 'always'}],
                'conditions': {'ref_name': {'include': [RUNTIME_REF], 'exclude': []}},
                'rules': [], 'target': 'tag'}.items():
                with self.subTest(index=index, key=key):
                    self.reject(lambda m: m['runtime_rulesets'][index].update({key: value}))
        for key, value in {'can_admins_bypass': True, 'prevent_self_review': False,
            'reviewer_ids': [], 'deployment_branches': [{'name': RUNTIME_REF.removeprefix('refs/heads/'), 'type': 'branch'}],
            'deployment_branch_policy': {'protected_branches': True, 'custom_branch_policies': False}}.items():
            self.reject(lambda m: m['environment_policy'].update({key: value}))

    def test_fixed_fault_authorization_proposal_budget_and_writer_constraints(self):
        self.assertEqual(f.pc.FAULTS, ('D03_REMOTE_REJECTION', 'D07_DROP_PATCH_RESPONSE'))
        self.assertEqual(f.pc.AUTHORIZATIONS, {'D03_REMOTE_REJECTION': 'P6WSV1-D03-01',
            'D07_DROP_PATCH_RESPONSE': 'P6WSV1-D07-01', '': 'P6WSV1-POSTRECOVERY-01'})
        self.assertEqual(f.pc.PROPOSALS, {'D03_REMOTE_REJECTION': 'p6ws-v1-d03',
            'D07_DROP_PATCH_RESPONSE': 'p6ws-v1-d07', '': 'p6ws-v1-postrecovery'})
        self.assertEqual(f.pc.BUDGET, {'consumptions': 2, 'authority_patch_attempts': 3,
            'authority_advances': 2, 'journal_patch_attempts': 12, 'journal_advances': 11})
        for operation in (*f.pc.FAULTS, ''):
            self.reject(lambda m: m['proposals'][operation].update(proposal_id='changed'))
            def rename(m):
                m['proposals'][operation+'changed'] = m['proposals'].pop(operation)
            self.reject(rename)
        for field in ('faults', 'authorizations'):
            plan = copy.deepcopy(f.pc.plan()[0]); plan[field] = []
            self.reject(lambda m: m.update(proof_plan_sha256=_digest(_canonical(plan))))
        for key in f.pc.BUDGET:
            self.reject(lambda m: m['budget'].update({key: m['budget'][key]+1}))
        for key, value in {'app_id': APP_ID+1, 'installation_id': INSTALLATION+1,
            'token_permissions': {'contents': 'write', 'metadata': 'read', 'administration': 'write'}}.items():
            self.reject(lambda m: m.update({key: value}))
        for key in ('writer_credential_source', 'd03_credential_source', 'ordinary_credential_source',
                    'environment', 'secret_name'):
            self.reject(lambda m: m['custody'].update({key: 'broader-or-inconsistent'}))

    def test_launcher_admission_without_q0_and_bound_host_context(self):
        env = x.environment(self.m)
        self.assertNotIn('P6WSV1_Q0_EVIDENCE', env)
        with patch.object(q, 'qualify_q0', side_effect=AssertionError('NO_Q0')):
            self.assertEqual(launcher.frozen(env), self.m)
        for key, value in {'GITHUB_REF': RUNTIME_REF, 'GITHUB_SHA': '0'*40,
            'GITHUB_WORKFLOW_REF': REPO+'/'+WORKFLOW+'@'+RUNTIME_REF,
            'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_EVENT_NAME': 'push',
            'RUNNER_ENVIRONMENT': 'self-hosted', 'GITHUB_ACTOR': 'owner',
            'GITHUB_TRIGGERING_ACTOR': 'owner', 'GITHUB_REPOSITORY_ID': '1'}.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                launcher.frozen(dict(env, **{key: value}))
        historical = f.setup()[1]
        with self.assertRaises(ValueError):
            launcher.frozen(x.environment(dict(historical, workflow_ref=self.m['workflow_ref'])))

    def launch(self, case, run):
        g, m = self.g, self.m
        env = x.environment(m, run)
        objects = []
        real_init = f.w._Writer.__init__
        def init(obj, **kwargs):
            real_init(obj, **kwargs)
            objects.append(obj)
            obj._call = g.api
        def get(suffix):
            if suffix.startswith('/collaborators/'):
                return {'user': f.pc.CALLER, 'role_name': 'write', 'permission': 'write'}
            return g.api('offline-token', 'GET', f.j.BASE+suffix)
        original_read = Path.read_bytes
        def read(path):
            if str(path) == env['GITHUB_EVENT_PATH']:
                return _canonical({'inputs': {'case': case}})
            return original_read(path)
        d03 = case == f.pc.FAULTS[0]
        g.status = 403 if d03 else 200
        g.expected_token = 'offline-job-token' if d03 else 'offline-token'
        g.error_body = _canonical({'message': 'Resource not accessible by integration'}) if d03 else None
        with patch.object(Path, 'read_bytes', read), patch.object(f.w._Writer, '__init__', init), \
             patch.object(collector.ReadOnlyRemote, 'get', side_effect=get), \
             patch.object(f.w.http.client, 'HTTPSConnection', side_effect=g.connection), \
             patch.object(f.jt, '_worker_log', side_effect=lambda: f.worker_raw(objects[-1])), \
             patch.object(q, 'qualify_q0', side_effect=AssertionError('NO_Q0')), \
             patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(io.StringIO()):
            return launcher.run(env)

    def complete(self):
        results = []
        for case, run in [(f.pc.FAULTS[0], 50), ('RECOVER', 51), (f.pc.FAULTS[1], 52),
                          ('RECOVER', 53), ('POSTRECOVERY', 54)]:
            result = self.launch(case, run)
            self.assertEqual(result['result'], 'RECOVERY_CONFIRMED' if case == 'RECOVER'
                             else 'COMMITTED' if case == 'POSTRECOVERY' else 'INDETERMINATE')
            if case != 'RECOVER':
                results.append(result)
        evidence = f.evidence(self.g, self.m, None, results)
        del evidence['q0']
        evidence['compatibility_admission'] = copy.deepcopy(self.m['compatibility_admission'])
        return evidence

    def collect(self, evidence):
        return collector.collect(self.m, evidence,
            lambda suffix: self.g.api('offline-token', 'GET', f.j.BASE+suffix))

    def test_complete_real_launcher_path_and_independent_collector(self):
        evidence = self.complete()
        with patch.object(collector, 'qualify_q0', side_effect=AssertionError('NO_Q0')), \
             patch.object(collector, 'verify_q0_objects', side_effect=AssertionError('NO_Q0')):
            result = self.collect(evidence)
        self.assertEqual(result['result'], 'PASS', result)
        self.assertEqual((self.g.authority_sends, self.g.journal_sends), (3, 12))
        journal = f.j.Journal(f.writer(self.g, self.m))
        self.assertEqual((len(journal.used), len(journal.rows)), (2, 11))
        before = (self.g.authority_sends, self.g.journal_sends)
        self.assertFalse(self.launch(f.pc.FAULTS[0], 55)['update_attempted'])
        self.assertFalse(self.launch(f.pc.FAULTS[1], 56)['update_attempted'])
        self.assertEqual((self.g.authority_sends, self.g.journal_sends), before)

    def test_collector_rejects_compat_runtime_provider_ruleset_and_reconstruction_changes(self):
        evidence = self.complete()
        self.assertEqual(self.collect(evidence)['result'], 'PASS')
        mutations = [lambda e: e.pop('compatibility_admission'),
            lambda e: e.update(q0={'schema': 'P6WSV1_Q0_V2', 'result': 'PASS'}),
            lambda e: e['compatibility_admission'].update(historical_q0_disposition='PASS'),
            lambda e: e['authority_attempts'][0].update(authorization='other'),
            lambda e: e['authority_attempts'][1].update(authorization='other'),
            lambda e: e['authority_attempts'][2].update(authorization='other'),
            lambda e: e['authority_attempts'][0].update(force=True),
            lambda e: e['journal_attempts'].pop(), lambda e: e.pop('raw_process'),
            lambda e: e['sibling'].update(loser=e['sibling']['winner'])]
        for i, mutate in enumerate(mutations):
            changed = copy.deepcopy(evidence); mutate(changed)
            with self.subTest(case=i):
                self.assertNotEqual(self.collect(changed)['result'], 'PASS')
        for index in (0, 1):
            key = str(self.m['runtime_rulesets'][index]['id'])
            observed = copy.deepcopy(self.g.rules[key]); observed['id'] += 100
            with patch.dict(self.g.rules, {key: observed}):
                self.assertNotEqual(self.collect(evidence)['result'], 'PASS')
        with patch.dict(self.g.refs, {EXEC_RUNTIME_REF: '0'*40}):
            self.assertNotEqual(self.collect(evidence)['result'], 'PASS')

    def test_launcher_provider_mismatch_rejects_before_writer_construction(self):
        key = str(self.m['runtime_rulesets'][0]['id'])
        observed = copy.deepcopy(self.g.rules[key]); observed['id'] += 100
        with patch.dict(self.g.rules, {key: observed}), self.assertRaises(ValueError):
            self.launch(f.pc.FAULTS[0], 50)
        self.assertEqual((self.g.authority_sends, self.g.journal_sends), (0, 0))

    def test_historical_q0_remains_separate_and_unchanged(self):
        g, m, q0 = f.setup()
        self.assertEqual(q.qualify_q0(m, q0)['result'], 'Q0_QUALIFIED')
        # Compatibility review does not become a historical evidence record.
        with self.assertRaises((ValueError, KeyError)):
            q.qualify_q0(m, self.m['compatibility_admission'])
        with self.assertRaises((ValueError, KeyError)):
            q.qualify_q0(self.m, q0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
