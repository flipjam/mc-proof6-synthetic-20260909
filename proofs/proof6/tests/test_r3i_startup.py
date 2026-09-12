"""Causal launch/custody regression and bounded source-scope checks."""
import ast
import contextlib
import copy
import errno
import inspect
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch
import yaml

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'proofs/proof6'))
import d04_signal as s
BASE='d4d0d448026b9f0dd0728a852d757543b550208e'


def identity(raw):
    return raw.replace(b'r3h',b'r3i').replace(b'R3H',b'R3I').replace(b'R3h',b'R3i').replace(
        b'd754156067cf1aa2318e7b04d7fcf47902eb9846',b'2cb629820e3bd04e7c7edaa2b2364682e4dc5f1b')


def original(path):
    return subprocess.check_output(['git','-C',str(ROOT),'show',BASE+':'+path])


class Launch(unittest.TestCase):
    def setUp(self):
        self.env={k:'PUBLIC' for k in s.PUBLIC_ENV}|{'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}
        self.helper=self.env|{s.TOKEN_SLOT:'STATUS_SENTINEL'}

    def test_hosted_48_extra_keys_rejected_by_unchanged_custody(self):
        extras={'DEBIAN_FRONTEND':'nonsecret'}|{'UNRELATED_%02d'%i:'nonsecret' for i in range(47)}
        dirty=self.helper|extras
        with self.assertRaises(ValueError):s.custody_values(True,dirty,[],{},True)
        self.assertEqual(s.launch_environment('setup-helper',dirty),self.helper)

    def test_all_accepted_custody_allowlists_unchanged(self):
        prior=ast.parse(original('proofs/proof6/d04_signal.py'))
        for name in ('PUBLIC_ENV','SYSTEM_ENV','WRITER_ENV'):
            node=next(n for n in prior.body if isinstance(n,ast.Assign) and n.targets[0].id==name)
            self.assertEqual(getattr(s,name),ast.literal_eval(node.value))

    def test_helper_status_retained_exactly(self):
        for role in ('helper','setup-helper'):
            self.assertEqual(s.launch_environment(role,self.helper)[s.TOKEN_SLOT],'STATUS_SENTINEL')

    def test_helper_missing_or_empty_status_rejected(self):
        for env in (self.env,self.env|{s.TOKEN_SLOT:''}):
            with self.assertRaises(ValueError):s.launch_environment('setup-helper',env)

    def test_wrong_App_delivery_rejected_before_filter(self):
        for role in ('helper','setup-helper','setup-peer'):
            for key in ('PROOF6_APP_TOKEN','PROOF6_APP_PRIVATE_KEY','PROOF6_APP_SLUG'):
                with self.assertRaises(ValueError):s.launch_environment(role,(self.helper if 'helper' in role else self.env)|{key:'APP_SENTINEL'})

    def test_status_never_scrubbed_to_hide_peer_or_writer_delivery(self):
        for role in ('setup-peer','writer'):
            for value in ('STATUS_SENTINEL',''):
                with self.assertRaises(ValueError):s.launch_environment(role,self.env|{s.TOKEN_SLOT:value})

    def test_other_job_tokens_rejected_before_filter(self):
        for role in ('helper','setup-helper','setup-peer','writer'):
            for key in ('GH_TOKEN','PROOF6_D03_JOB_TOKEN'):
                with self.assertRaises(ValueError):s.launch_environment(role,self.helper|{key:'SENTINEL'})

    def test_writer_retains_existing_App_and_public_inputs_only(self):
        env=self.env|{k:'VALUE' for k in s.WRITER_ENV}|{'UNRELATED':'VALUE'}
        result=s.launch_environment('writer',env)
        self.assertEqual(set(result),set(env)-{'UNRELATED'})
        with self.assertRaises(ValueError):s.launch_environment('writer',env|{'PROOF6_APP_PRIVATE_KEY':'KEY'})

    def test_unknown_role_cannot_select_command(self):
        for role in ('arbitrary','/bin/bash','cleanup','serve'):
            with self.assertRaises(ValueError):s.launch_environment(role,self.helper)

    def test_fixed_exec_environment_and_no_token_in_argv(self):
        modes={'helper':('120s','serve'),'setup-helper':('120s','serve-setup'),'setup-peer':('20s','qualify-setup')}
        for role,(duration,mode) in modes.items():
            env=(self.helper if role!='setup-peer' else self.env)|{'UNRELATED':'VALUE'}
            with patch.dict(os.environ,env,clear=True),patch.object(s,'binding'),patch.object(s.os,'execve') as execute:
                s.launch(role)
            executable,argv,delivered=execute.call_args.args
            self.assertEqual(executable,'/usr/bin/timeout')
            self.assertEqual(argv,['/usr/bin/timeout','--signal=KILL',duration,'/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py',mode])
            self.assertNotIn('STATUS_SENTINEL',str(argv));self.assertNotIn('UNRELATED',delivered)

    def test_writer_exec_preserves_actual_writer_argv(self):
        with patch.dict(os.environ,self.env,clear=True),patch.object(s,'binding'),patch.object(s.os,'execve') as execute:s.launch('writer')
        self.assertEqual(execute.call_args.args[:2],('/usr/bin/python3',['/usr/bin/python3','-B','proofs/proof6/actions_runtime.py']))

    def test_exec_failure_has_bounded_errno_and_no_exception_text(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            s.startup_stage('LAUNCH_EXEC');s.startup_failure(OSError(errno.EACCES,'SECRET_SENTINEL'))
        self.assertNotIn('SECRET_SENTINEL',output.getvalue())
        value=json.loads(output.getvalue().splitlines()[-1].split(' ',1)[1])
        self.assertEqual((value['stage'],value['errno'],value['errno_name']),('LAUNCH_EXEC',13,'EACCES'))

    def test_unknown_stage_rejected(self):
        with self.assertRaises(ValueError):s.startup_stage('ARBITRARY_SECRET')

    def test_no_launch_provider_or_mutation_calls(self):
        source=inspect.getsource(s.launch)+inspect.getsource(s.launch_environment)
        for forbidden in ('status_request','urlopen','journal','writer.','socket.','write_bytes','write_text','subprocess'):
            self.assertNotIn(forbidden,source)


class Scope(unittest.TestCase):
    def test_existing_signal_functions_identical_after_removing_stage_records(self):
        class RemoveStages(ast.NodeTransformer):
            def visit_Expr(self,node):
                if isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=='startup_stage':return None
                return self.generic_visit(node)
        old=ast.parse(identity(original('proofs/proof6/d04_signal.py')))
        new=RemoveStages().visit(ast.parse((ROOT/'proofs/proof6/d04_signal.py').read_bytes()))
        old_defs={n.name:ast.dump(n) for n in old.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        new_defs={n.name:ast.dump(n) for n in new.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        self.assertEqual(old_defs,{k:new_defs[k] for k in old_defs})

    def test_launch_policy_is_only_signal_policy_addition(self):
        old=json.loads(original('proofs/proof6/proof_plan.json'))['d04_signal']
        old=json.loads(identity(json.dumps(old).encode()))
        current=copy.deepcopy(s.POLICY);addition=current.pop('launch_environment')
        self.assertEqual(current,old);self.assertFalse(addition['new_permissions'])

    def test_original_R3h_tests_preserved_exactly(self):
        for path in subprocess.check_output(['git','-C',str(ROOT),'ls-tree','-r','--name-only',BASE,'proofs/proof6/tests']).decode().splitlines():
            if path.endswith('.py') and not path.endswith('/support.py'):
                self.assertEqual((ROOT/path).read_bytes(),original(path),path)

    def test_scope_critical_modules_preserved(self):
        for name in ('outage.py','admission.py','reconcile.py','d03_rejection.py','sibling_canary.py','diagnostics.py','ruleset_view.py'):
            self.assertEqual((ROOT/'proofs/proof6'/name).read_bytes(),original('proofs/proof6/'+name))

    def test_no_new_workflow_permission_or_trigger(self):
        old=yaml.safe_load(original('.github/workflows/proof6-writer.yml'))
        current=yaml.safe_load((ROOT/'.github/workflows/proof6-writer.yml').read_bytes())
        self.assertEqual({k:v for k,v in old.items() if k!='jobs'},{k:v for k,v in current.items() if k!='jobs'})
        self.assertEqual(set(old['jobs']),set(current['jobs']))
        for key in old['jobs']:self.assertEqual(old['jobs'][key]['permissions'],current['jobs'][key]['permissions'])

    def test_fixed_setup_launch_and_failure_output_before_exit(self):
        flow=yaml.safe_load((ROOT/'.github/workflows/proof6-writer.yml').read_bytes())
        steps=flow['jobs']['signal_setup']['steps']
        self.assertIn('d04_signal.py launch-setup &',steps[1]['run'])
        self.assertIn('d04_signal.py launch-peer </dev/null',steps[2]['run'])
        cleanup=steps[-1]['run']
        self.assertLess(cleanup.index('set +e'),cleanup.index('result=$('))
        self.assertLess(cleanup.index('printf'),cleanup.index('exit "$cleanup_exit"'))
        self.assertLess(cleanup.index('replay-startup'),cleanup.index('exit "$cleanup_exit"'))
        self.assertLess(cleanup.index('if test "$cleanup_exit" -ne 0'),cleanup.index('replay-startup'))


if __name__=='__main__':
    with patch.object(socket,'socket',side_effect=AssertionError('OFFLINE_ONLY')):
        unittest.main(verbosity=2)
