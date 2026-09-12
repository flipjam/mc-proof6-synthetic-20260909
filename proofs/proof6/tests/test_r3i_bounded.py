"""Bounded correction/source and non-consuming bootstrap assertions."""
import copy
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch
import yaml
from test_r3i_startup import identity
import support
import d04_signal as s

ROOT=support.ROOT
PARTIAL='032076ffbcd1056c3f8f99d096e07214421e13c9'


class Bootstrap(unittest.TestCase):
    def setUp(self):self.fixture=support.legacy.Bootstrap()

    def test_valid_bound_setup_receipt_bootstraps_without_mutation(self):
        code,result,calls=self.fixture.route()
        self.assertEqual((code,calls),(0,1))
        for k in ('acceptance_credit','update_attempted','journal_mutation_attempted','proof_consumption_attempted'):
            self.assertIs(result[k],False)
        self.assertTrue(result['d04_signal_setup_qualification']['helper_reaped'])
        self.assertTrue(result['d04_signal_setup_qualification']['producer_reaped'])

    def test_missing_signal_setup_blocks_before_App_diagnostic(self):
        self.fixture.blocked(env_change={'PROOF6_D04_SIGNAL_SETUP_QUALIFICATION':''})

    def test_missing_isolation_setup_still_blocks(self):
        self.fixture.blocked(env_change={'PROOF6_D04_SETUP_QUALIFICATION':''})

    def invalid(self,mutate):
        value=json.loads(self.fixture.context()['PROOF6_D04_SIGNAL_SETUP_QUALIFICATION'])
        mutate(value)
        self.fixture.blocked(env_change={'PROOF6_D04_SIGNAL_SETUP_QUALIFICATION':json.dumps(value)})

    def test_wrong_run_attempt_runtime_or_target_blocks(self):
        for key,value in [('run_id',51),('attempt',2),('runtime_sha','b'*40),('target_sha','b'*40),('context','other')]:
            with self.subTest(key=key):self.invalid(lambda x:x['binding'].update({key:value}))

    def test_unreaped_helper_or_producer_blocks(self):
        for key in ('helper_reaped','producer_reaped'):
            self.invalid(lambda x:x.update({key:False}))

    def test_wrong_effective_permission_blocks(self):
        self.invalid(lambda x:x['permissions'].update(Contents='read'))

    def test_custody_failure_blocks(self):self.invalid(lambda x:x.update(custody=False))

    def test_unknown_runner_blocks(self):self.invalid(lambda x:x.update(runner_version='0.0.0'))

    def test_unknown_runner_commit_blocks(self):self.invalid(lambda x:x.update(runner_commit='0'*40))

    def test_status_POST_or_acceptance_credit_blocks(self):
        self.invalid(lambda x:x.update(status_posts=1))
        self.invalid(lambda x:x.update(acceptance_credit=True))

    def test_extra_credential_or_wrong_types_block(self):
        self.invalid(lambda x:x.update(token='SYNTHETIC_ONLY'))
        self.invalid(lambda x:x.update(helper_reaped=1))
        self.invalid(lambda x:x['binding'].update(attempt=True))

    def test_same_or_invalid_process_identity_blocks(self):
        self.invalid(lambda x:x.update(helper_pid=x['producer_pid']))
        self.invalid(lambda x:x.update(helper_pid=True))


class Scope(unittest.TestCase):
    def setUp(self):
        self.path='.github/workflows/proof6-writer.yml'
        self.flow=yaml.load((ROOT/self.path).read_bytes(),Loader=yaml.BaseLoader)
        self.old=yaml.load(identity(subprocess.check_output(['git','-C',str(ROOT),'show',PARTIAL+':'+self.path])),Loader=yaml.BaseLoader)

    def test_D04_workflow_job_byte_semantics_unchanged(self):
        actual=copy.deepcopy(self.flow['jobs']['d04_writer'])
        old=self.old['jobs']['d04_writer']
        for step in actual['steps']:
            if 'run' not in step:continue
            step['run']=step['run'].replace('/usr/bin/python3 -I -B proofs/proof6/d04_signal.py launch-helper &',
                '/usr/bin/timeout --signal=KILL 120s /usr/bin/python3 -I -B proofs/proof6/d04_signal.py serve &')
            step['run']=step['run'].replace('/usr/bin/python3 -I -B proofs/proof6/d04_signal.py launch-writer </dev/null',
                '/usr/bin/python3 -B proofs/proof6/actions_runtime.py </dev/null')
        prior_cleanup=old['steps'][-1]['run']
        line=next(x for x in prior_cleanup.splitlines() if 'd04_signal.py cleanup' in x)
        expected=prior_cleanup.replace('set -euo pipefail','set +e').replace(line,line+'\ncleanup_exit=$?\nif test "$cleanup_exit" -ne 0; then\n  '+line.replace('d04_signal.py cleanup','d04_signal.py replay-startup')+'\nfi\nexit "$cleanup_exit"')
        self.assertEqual(actual['steps'][-1]['run'],expected)
        actual['steps'][-1]['run']=prior_cleanup
        self.assertEqual(old,actual)

    def test_setup_exact_permission_and_no_App_action(self):
        job=self.flow['jobs']['signal_setup']
        self.assertEqual(job['permissions'],{'statuses':'write'})
        self.assertEqual(job['environment'],'proof6-writer')
        self.assertEqual(job['runs-on'],'ubuntu-24.04')
        self.assertEqual(job['timeout-minutes'],'3')
        for step in job['steps']:
            self.assertNotIn('uses',step)
            self.assertNotIn('PROOF6_APP',step.get('run',''))
            self.assertNotIn('secrets.',str(step))

    def test_setup_token_delivered_only_to_helper_step(self):
        job=self.flow['jobs']['signal_setup']
        deliveries=[step for step in job['steps'] if 'github.token' in str(step)]
        self.assertEqual(len(deliveries),1)
        self.assertEqual(deliveries[0]['env'],{s.TOKEN_SLOT:'${{ github.token }}'})
        self.assertIn('d04_signal.py launch-setup &',deliveries[0]['run'])
        self.assertIn('wait "$native"',deliveries[0]['run'])
        peer=next(x for x in job['steps'] if 'launch-peer' in x.get('run',''))
        self.assertNotIn('env',peer);self.assertNotIn(s.TOKEN_SLOT,peer['run'])
        self.assertIn("'20s' if role == 'setup-peer'",inspect.getsource(s.launch));self.assertIn('</dev/null',peer['run'])

    def test_setup_gate_and_frozen_recovery_behavior(self):
        job=self.flow['jobs']['signal_setup'];writer=self.flow['jobs']['writer']
        self.assertIn("inputs.proof_operation == '' && inputs.proposal == ''",job['if'])
        for step in job['steps']:self.assertIn("vars.PROOF6_FROZEN_MANIFEST == ''",step['if'])
        self.assertEqual(writer['needs'],'signal_setup')
        prefix="always() && !cancelled() && (needs.signal_setup.result == 'success' || needs.signal_setup.result == 'skipped') && "
        self.assertEqual(writer['if'],prefix+self.old['jobs']['writer']['if'])
        self.assertEqual(job['steps'][-1]['if'],"always() && vars.PROOF6_FROZEN_MANIFEST == ''")
        self.assertIn('cleanup-setup',job['steps'][-1]['run'])
        self.assertEqual(job['outputs'],{'qualification':'${{ steps.qualified.outputs.qualification }}'})

    def test_only_authorized_normal_job_wiring_changed(self):
        actual=copy.deepcopy(self.flow['jobs']['writer']);old=self.old['jobs']['writer']
        actual.pop('needs');actual['if']=old['if']
        execute=next(x for x in actual['steps'] if x.get('id')=='execute')
        self.assertEqual(execute['env'].pop('PROOF6_D04_SIGNAL_SETUP_QUALIFICATION'),'${{ needs.signal_setup.outputs.qualification }}')
        execute['run']=execute['run'].replace('--preserve-env=PROOF6_D04_SIGNAL_SETUP_QUALIFICATION,','--preserve-env=')
        self.assertEqual(actual,old)
        self.assertEqual({k:v for k,v in self.flow.items() if k!='jobs'},{k:v for k,v in self.old.items() if k!='jobs'})

    def test_plan_all_rows_and_campaign_except_S1_unchanged(self):
        path='proofs/proof6/proof_plan.json'
        old=json.loads(identity(subprocess.check_output(['git','-C',str(ROOT),'show',PARTIAL+':'+path])))
        new=json.loads((ROOT/path).read_bytes())
        for key in ('cases','accounting','workflow_budget','order'):self.assertEqual(new[key],old[key])
        for key in old['workflow_runs']:
            if key!='S1':self.assertEqual(new['workflow_runs'][key],old['workflow_runs'][key])
        self.assertEqual(len(new['cases']),72)
        self.assertEqual(new['d04_signal']['observer_policy'],old['d04_signal']['observer_policy'])
        self.assertEqual(new['d04_signal']['verification_limit'],old['d04_signal']['verification_limit'])

    def test_original_safety_modules_byte_identical_to_partial(self):
        for name in ('writer.py','journal.py','outage.py','d03_job_token.py','d03_rejection.py','d04_capability.py',
                     'd04_prerequisite.py','app_probes.py','admission.py','reconcile.py','sibling_canary.py'):
            path='proofs/proof6/'+name
            self.assertEqual((ROOT/path).read_bytes(),identity(subprocess.check_output(['git','-C',str(ROOT),'show',PARTIAL+':'+path])),name)

    def test_setup_source_no_authority_or_acceptance_path(self):
        source=inspect.getsource(s.qualify_setup)
        for forbidden in ('status_request','READY','END','PROOF6_APP','_worker_log','read_bytes','read_text'):
            self.assertNotIn(forbidden,source)
        source=inspect.getsource(s._serve)
        start=source.index('if setup:\n                conn.settimeout')
        end=source.index("            packet(conn, dict(marker, phase='QUALIFIED'))")
        branch=source[start:end]
        self.assertIn('return',branch)
        for forbidden in ('status_request','event_valid','READY','END','journal','isolate_runtime'):
            self.assertNotIn(forbidden,branch)
        self.assertIn('preflight = None if setup else status_request(token, b)',source)


if __name__=='__main__':
    with patch.object(socket,'socket',side_effect=AssertionError('OFFLINE_ONLY')):
        unittest.main(verbosity=2)
