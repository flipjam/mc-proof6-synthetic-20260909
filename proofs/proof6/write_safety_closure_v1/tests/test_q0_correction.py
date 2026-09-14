"""Bounded Q0 counterexamples; reseal metadata to exercise semantics, not hashes."""
import copy
import socket
import unittest
from unittest.mock import patch
from fixtures import setup, q, j, _canonical, _digest
import collector
import q0_evidence as qe


class Q0Correction(unittest.TestCase):
    def setUp(self):
        sockets = patch.object(socket, 'socket', side_effect=AssertionError('OFFLINE_ONLY'))
        sockets.start(); self.addCleanup(sockets.stop)
        self.g, self.m, self.e = setup()

    def reseal(self):
        c = self.m['custody']
        if 'ordinary_inventory' in self.e:
            c['inventory_sha256'] = _digest(_canonical(self.e['ordinary_inventory']))
        if 'writer_custody' in self.e:
            c['provider_custody_sha256'] = _digest(_canonical(self.e['writer_custody']))
        self.e['custody'] = copy.deepcopy(c)
        self.m['q0_evidence_sha256'] = _digest(_canonical(self.e))

    def result(self):
        self.reseal()
        return collector.collect_q0(self.m, self.e,
            lambda suffix: self.g.api('offline-token', 'GET', j.BASE+suffix))['result']

    def rejected(self):
        self.assertEqual(self.result(), 'NOT_PASS')
        self.assertEqual((self.g.authority_sends, self.g.journal_sends), (0, 0))

    def test_01_correct_account_wrong_hostname(self):
        self.e['ordinary_inventory']['context']['hostname'] = 'DEV-MACHINE'
        self.rejected()

    def test_02_dev_evidence_mislabeled_ordinary(self):
        self.assertEqual(self.e['ordinary_inventory']['context']['hostname'], qe.HOST)
        self.e['ordinary_inventory']['observation_context']['hostname'] = 'DEV-MACHINE'
        self.rejected()

    def test_03_unexpected_second_usable_credential(self):
        additional = copy.deepcopy(self.e['ordinary_inventory']['credentials'][0])
        additional['credential_id'] = 'second-usable-credential'
        self.e['ordinary_inventory']['credentials'].append(additional)
        self.rejected()

    def test_04_writer_credential_reachable(self):
        env = next(d for d in self.e['ordinary_inventory']['discovery'] if d['surface'] == 'environment')
        env['entries'][0]['environment_slot'] = 'P6WSV1_APP_PRIVATE_KEY'
        self.rejected()

    def test_05_admin_credential_reachable(self):
        self.e['ordinary_inventory']['credentials'][0]['account']['admin'] = True
        self.e['ordinary_inventory']['credentials'][0]['account']['role'] = 'admin'
        self.rejected()

    def test_06_missing_provider_inventory(self):
        self.e['ordinary_inventory']['discovery'] = []
        self.rejected()

    def test_07_missing_provider_custody(self):
        self.e.pop('writer_custody')
        self.rejected()

    def test_08_missing_environment_secret_metadata(self):
        self.e['writer_custody'].pop('secret_metadata')
        self.rejected()

    def test_09_different_credential_provider(self):
        self.e['denials'][0]['credential_resolution']['credential_id'] = 'dev-admin-profile'
        self.rejected()

    def test_10_only_one_authority_path(self):
        self.e['denials'].pop(1)
        self.rejected()

    def test_11_generic_403_no_valid_request(self):
        self.e['denials'][1]['response'] = {'status': 403}
        self.rejected()

    def test_12_generic_422_malformed_candidate(self):
        r = self.e['denials'][1]
        r['response']['status'] = 422
        r['response']['classification'] = 'VALIDATION_FAILED'
        r['candidate_commit']['status'] = 404
        self.rejected()

    def test_13_wrong_repository_or_ref(self):
        for field in ('repository', 'ref'):
            with self.subTest(field=field):
                saved = copy.deepcopy(self.e)
                if field == 'repository':
                    self.e['denials'][0]['repository'] = 'unrelated/repo'
                else:
                    self.e['denials'][0]['request']['ref'] = qe.CONTROL_REF
                self.rejected()
                self.e = saved

    def test_14_authority_not_meaningful_fast_forward(self):
        for invalid in ('wrong_parent', 'unchanged_tree'):
            with self.subTest(invalid=invalid):
                saved = copy.deepcopy(self.e)
                r = self.e['denials'][0]
                if invalid == 'wrong_parent':
                    r['candidate_commit']['body']['parents'] = [{'sha': 'e'*40}]
                else:
                    r['candidate_commit']['body']['tree'] = copy.deepcopy(r['before_commit']['body']['tree'])
                self.rejected()
                self.e = saved

    def test_15_missing_denial_classification(self):
        self.e['denials'][1]['response'].pop('classification')
        self.rejected()

    def test_16_changed_protected_ref_despite_denial(self):
        r = self.e['denials'][0]
        r['after'] = r['candidate']
        r['after_read']['body']['object']['sha'] = r['candidate']
        self.rejected()

    def test_17_complete_structured_q0(self):
        self.assertEqual(self.result(), 'PASS')
        self.assertEqual((self.g.authority_sends, self.g.journal_sends), (0, 0))

    def test_18_fabricated_provider_suite(self):
        suite = self.e['denials'][0]['policy_evaluation']
        suite['body']['id'] = 777777
        suite['endpoint'] = qe.PREFIX+'/rulesets/rule-suites/777777'
        self.reseal()
        # Structurally plausible archived metadata is insufficient: re-read fails.
        self.assertEqual(q.qualify_q0(self.m, self.e)['result'], 'Q0_QUALIFIED')
        self.assertEqual(self.result(), 'BLOCKED')

    def test_19_provider_disagrees_with_candidate(self):
        sha = self.e['denials'][0]['candidate']
        self.g.objects[sha]['parents'] = [{'sha': 'e'*40}]
        self.rejected()

    def test_20_provider_app_can_administer(self):
        self.e['writer_custody']['app']['body']['permissions']['administration'] = 'write'
        self.rejected()

    def test_21_provider_environment_runtime_or_scope_mismatch(self):
        for area in ('environment', 'runtime', 'scope'):
            with self.subTest(area=area):
                saved = copy.deepcopy(self.e)
                provider = self.e['writer_custody']
                if area == 'environment':
                    provider['environment']['body']['name'] = 'other-environment'
                elif area == 'runtime':
                    provider['runtime_ref']['body']['object']['sha'] = 'e'*40
                else:
                    provider['repository_scope']['body']['total_count'] = 2
                self.rejected()
                self.e = saved

    def test_22_incomplete_or_unknown_provider_discovery(self):
        for field, value in (('next_cursor', 'more'), ('errors', ['access-denied']), ('source', 'local-pass')):
            with self.subTest(field=field):
                saved = copy.deepcopy(self.e)
                self.e['ordinary_inventory']['discovery'][0][field] = value
                self.rejected()
                self.e = saved

    def test_23_same_suite_cannot_cover_both_authority_paths(self):
        self.e['denials'][1]['policy_evaluation'] = copy.deepcopy(self.e['denials'][0]['policy_evaluation'])
        self.rejected()

    def test_24_type_confusion(self):
        self.e['denials'][1]['request']['body']['force'] = 0
        self.rejected()

    def test_25_unsealed_inventory_change(self):
        self.e['ordinary_inventory']['credentials'][0]['store_target'] = 'another-profile'
        # The runtime freeze, not a caller-selected request, owns the seal.
        self.m['q0_evidence_sha256'] = _digest(_canonical(self.e))
        with self.assertRaises(ValueError):
            q.qualify_q0(self.m, self.e)

    def test_26_probe_executed_in_other_context(self):
        self.e['denials'][0]['execution_context']['user_sid'] = 'S-1-5-21-999-888-777-1001'
        self.rejected()

    def test_27_reachable_github_ssh_key(self):
        row = next(d for d in self.e['ordinary_inventory']['discovery'] if d['surface'] == 'ssh')
        entry = copy.deepcopy(self.e['ordinary_inventory']['discovery'][0]['entries'][0])
        entry['ssh_public_fingerprint'] = 'SHA256:public-fingerprint-fixture'
        row['entries'] = [entry]; row['total_count'] = 1
        self.rejected()

    def test_28_422_with_valid_policy_evidence_can_qualify(self):
        for r in self.e['denials'][1:]:
            r['response']['status'] = 422
        self.assertEqual(self.result(), 'PASS')

    def test_29_auth_rate_network_or_local_failure(self):
        for classification in ('AUTHENTICATION_FAILED', 'RATE_LIMITED', 'NETWORK_FAILED', 'LOCAL_FAILURE'):
            with self.subTest(classification=classification):
                self.e['denials'][1]['response']['classification'] = classification
                self.rejected()

    def test_30_evaluate_only_rule_does_not_prove_enforcement(self):
        self.e['denials'][0]['policy_evaluation']['body']['rule_evaluations'][0]['enforcement'] = 'evaluate'
        self.rejected()


if __name__ == '__main__':
    unittest.main(verbosity=2)
