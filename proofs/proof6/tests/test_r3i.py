"""Offline successor counterexamples. No provider call or acceptance credit."""
import ast
import copy
import inspect
import io
import json
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import Mock, patch
import yaml
import r3i_prior as prior
import d04_signal as s

ROOT = prior.module.ROOT
f = prior.module.f
ar = prior.module.ar
B = {'run_id': 12345, 'attempt': 1, 'runtime_sha': 'a'*40, 'target_sha': 'a'*40,
     'context': 'proof6/d04-signal/12345/1/' + 'a'*40}


def event(phase='READY', stamp=100):
    record = f.child()
    return dict(schema=s.SCHEMA, binding=copy.deepcopy(B), pid=record['context']['pid'], phase=phase,
                monotonic=stamp, utc='2026-09-12T20:00:00+00:00', observation=record)


class Events(unittest.TestCase):
    def check(self, item, phase='READY', ready=None, now=100):
        return s.event_valid(item, B, f.child()['context']['pid'], phase, ready, now)

    def test_qualified_ready(self):
        self.check(event())

    def test_exact_run_attempt_runtime_target_context(self):
        for key in B:
            item=event();item['binding'][key]=False if type(B[key]) is int else 'other'
            with self.subTest(key=key),self.assertRaises(ValueError):self.check(item)

    def test_boolean_attempt_rejected(self):
        item=event();item['binding']['attempt']=True
        with self.assertRaises(ValueError):self.check(item)

    def test_stale_and_future_ready(self):
        for stamp in (94,101,float('nan'),float('inf'),True):
            with self.subTest(stamp=stamp),self.assertRaises(ValueError):self.check(event(stamp=stamp))

    def test_malformed_extra_and_missing_fields(self):
        for item in (dict(event(),secret='SENTINEL'),{},None,dict(event(),schema='old')):
            with self.assertRaises((ValueError,TypeError,KeyError)):self.check(item)

    def test_duplicate_json_and_oversize_rejected(self):
        for raw in (b'{"a":1,"a":2}',b'x'*16385):
            with self.assertRaises(ValueError):s.decode(raw)

    def test_unqualified_actual_writer_rejected(self):
        item=event();item['observation']['qualified']=False
        with self.assertRaises(ValueError):self.check(item)

    def test_wrong_actual_pid_rejected(self):
        item=event();item['pid']+=1
        with self.assertRaises(ValueError):self.check(item)

    def test_helper_prerequisite_cannot_be_ready(self):
        item=event();item['observation']=f.prerequisite()
        with self.assertRaises((ValueError,KeyError)):self.check(item)

    def test_end_before_ready_rejected(self):
        with self.assertRaises(ValueError):self.check(event('END',130),'END',now=130)

    def test_early_end_rejected(self):
        with self.assertRaises(ValueError):self.check(event('END',129.999),'END',event(),130)

    def test_end_at_30_seconds_qualified(self):
        self.check(event('END',130),'END',event(),130)

    def test_failed_fresh_end_rejected(self):
        item=event('END',130);item['observation']['ipv4']['read_success']=False
        with self.assertRaises(ValueError):self.check(item,'END',event(),130)

    def test_duplicate_ready_and_contradictory_end(self):
        with self.assertRaises(ValueError):self.check(event(),ready=event())
        with self.assertRaises(ValueError):self.check(event('END',130),now=130)

    def test_socket_packet_truncation_and_eof(self):
        for raw,flags in ((b'',0),(b'{}',32)):
            sock=Mock();sock.recvmsg.return_value=(raw,[],flags,None)
            with patch.object(s.socket,'MSG_TRUNC',32,create=True),self.assertRaises(ValueError):s.receive(sock)

    def test_ancillary_descriptor_delivery_and_noncanonical_packet_rejected(self):
        for raw,ancillary,flags in ((b'{}',[(1,1,b'fake-fd')],0),(b'{}',[],8),(b'{ "a": 1 }',[],0)):
            sock=Mock();sock.recvmsg.return_value=(raw,ancillary,flags,None)
            with self.assertRaises(ValueError):s.receive(sock)


class Custody(unittest.TestCase):
    def fixture(self, helper):
        env={s.TOKEN_SLOT:b'STATUS_SENTINEL'} if helper else {'PROOF6_APP_TOKEN':b'APP_SENTINEL'}
        argv=[b'/usr/bin/python3',b'-I',b'-B',b'proofs/proof6/d04_signal.py',b'serve'] if helper else [b'/usr/bin/python3',b'-B',b'proofs/proof6/actions_runtime.py']
        target=str(s.directory(B)/'helper.log') if helper else 'pipe:[123]'
        return env,argv,{0:('/dev/null',os.O_RDONLY),1:(target,os.O_WRONLY),2:(target,os.O_WRONLY)}

    def test_exact_roles_no_secret_in_receipt(self):
        with patch.object(s,'binding',return_value=B):
            for helper in (True,False):
                value=s.custody_values(helper,*self.fixture(helper))
                self.assertNotIn('SENTINEL',json.dumps(value));self.assertFalse(value['acceptance_credit'])

    def test_status_environment_in_writer_fails(self):
        env,args,fds=self.fixture(False);env[s.TOKEN_SLOT]=b'STATUS_SENTINEL'
        with self.assertRaises(ValueError):s.custody_values(False,env,args,fds)

    def test_app_environment_in_helper_fails(self):
        for key in ('PROOF6_APP_TOKEN','PROOF6_APP_PRIVATE_KEY','GH_TOKEN'):
            env,args,fds=self.fixture(True);env[key]=b'APP_SENTINEL'
            with self.assertRaises(ValueError):s.custody_values(True,env,args,fds)

    def test_unrecognized_environment_alias_fails(self):
        for helper in (True,False):
            env,args,fds=self.fixture(helper);env['OTHER_CREDENTIAL']=b'SENTINEL'
            with self.assertRaises(ValueError):s.custody_values(helper,env,args,fds)

    def test_argv_exposure_fails(self):
        for helper in (True,False):
            env,args,fds=self.fixture(helper);args.append(b'SENTINEL')
            with self.assertRaises(ValueError):s.custody_values(helper,env,args,fds)

    def test_inherited_secret_descriptor_fails(self):
        for helper in (True,False):
            env,args,fds=self.fixture(helper);fds[3]=('/tmp/credential',os.O_RDONLY)
            with self.assertRaises(ValueError):s.custody_values(helper,env,args,fds)

    def test_shared_credential_file_stdin_fails(self):
        for helper in (True,False):
            env,args,fds=self.fixture(helper);fds[0]=('/tmp/credential',os.O_RDONLY)
            with self.assertRaises(ValueError):s.custody_values(helper,env,args,fds)

    def test_readable_output_descriptor_fails(self):
        env,args,fds=self.fixture(True);fds[1]=(str(s.directory(B)/'helper.log'),os.O_RDWR)
        with self.assertRaises(ValueError):s.custody_values(True,env,args,fds)

    def test_token_ipc_payload_fails(self):
        item=event();item['credential']='SENTINEL'
        with self.assertRaises(ValueError):s.event_valid(item,B,item['pid'],'READY',now=100)

    def test_helper_hello_rejects_nested_extra_credential_data(self):
        preflight=dict(started_at=s.utc(),completed_at=s.utc(),http_status=200,date=None,request_id=None,payload=None)
        value=dict(schema=s.SCHEMA,binding=B,phase='QUALIFIED',pid=100,permissions=s.PERMISSIONS,provider_preflight=preflight,deadline=100)
        s.hello_valid(value,B)
        preflight['credential']='SENTINEL'
        with self.assertRaises(ValueError):s.hello_valid(value,B)

    def test_writer_client_has_no_discovery_or_api_path(self):
        source=inspect.getsource(s.Client)
        for forbidden in ('status_request(', '_worker_log(', 'open(', 'read_bytes(', 'read_text(', 'Popen', 'PROOF6_APP_TOKEN'):
            self.assertNotIn(forbidden,source)
        self.assertEqual(list(inspect.signature(s.Client).parameters),[])
        self.assertIn("'/proc/self/environ'",inspect.getsource(s.custody))


class Permissions(unittest.TestCase):
    def record(self,permissions=None,job='d04_writer'):
        expected={'repository':s.REPO,'repository_id':'1363510385','ref':s.RUNTIME,
            'workflow_ref':s.REPO+'/.github/workflows/proof6-writer.yml@'+s.RUNTIME,
            'sha':B['runtime_sha'],'run_id':str(B['run_id']),'run_attempt':'1','event_name':'workflow_dispatch'}
        message={'variables':{'system.github.token.permissions':{'value':json.dumps(s.PERMISSIONS if permissions is None else permissions)},
            'system.github.job':{'value':job}},'contextData':{'github':{'t':2,'d':[{'k':k,'v':v} for k,v in expected.items()]}},
            'jobId':'12345678-1234-1234-1234-123456789abc'}
        prefix=f'[now INFO Worker] Version: {s.RUNNER_VERSION}\n[now INFO Worker] Commit: {s.RUNNER_COMMIT}\n[now INFO Worker] Job message:\n'
        return prefix.encode()+json.dumps(message).encode()

    def test_exact_effective_scope(self):
        raw=self.record();stream=io.BytesIO(raw)
        self.assertEqual(s.masked_worker_record(stream),raw)
        result=s._permission_evidence(raw,B)
        self.assertEqual(result['permissions'],{'Metadata':'read','Statuses':'write'})
        self.assertNotIn('variables',result)

    def test_broader_or_missing_effective_scope_rejected(self):
        for permissions in ({'Metadata':'read'},dict(s.PERMISSIONS,Contents='read'),dict(s.PERMISSIONS,Contents='write'),
                            dict(s.PERMISSIONS,Actions='read'),dict(s.PERMISSIONS,Administration='write'),{'Metadata':'read','Statuses':'read'}):
            with self.subTest(permissions=permissions),self.assertRaises(ValueError):s._permission_evidence(self.record(permissions),B)

    def test_wrong_job_source_rejected(self):
        with self.assertRaises(ValueError):s._permission_evidence(self.record(job='writer'),B)

    def test_unknown_runner_blocked_before_job_payload_read(self):
        raw=self.record().replace(s.RUNNER_COMMIT.encode(),b'0'*40)
        stream=io.BytesIO(raw)
        with self.assertRaises(ValueError):s.masked_worker_record(stream)
        self.assertEqual(stream.read(1),b'{')

    def test_missing_audited_header_rejected(self):
        with self.assertRaises(ValueError):s.masked_worker_record(io.BytesIO(b'not-header\n'))


class Deadline(unittest.TestCase):
    def client(self,remaining):
        obj=object.__new__(s.Client);obj.deadline=100+remaining;obj.socket=Mock()
        obj.socket.recv.side_effect=BlockingIOError();return obj

    def test_fifty_second_reserve_required(self):
        with patch.object(s.time,'monotonic',return_value=100):
            for n in (0,30,49.999):
                with self.assertRaises(ValueError):self.client(n).qualify()

    def test_live_idle_channel_qualified_and_timeout_restored(self):
        obj=self.client(50);obj.socket.gettimeout.return_value=8
        with patch.object(s.time,'monotonic',return_value=100),patch.object(s.socket,'MSG_DONTWAIT',64,create=True):obj.qualify()
        obj.socket.settimeout.assert_called_with(8)

    def test_eof_or_unsolicited_packet_fails(self):
        for raw in (b'',b'x'):
            obj=self.client(60);obj.socket.recv.side_effect=None;obj.socket.recv.return_value=raw
            with patch.object(s.time,'monotonic',return_value=100),patch.object(s.socket,'MSG_DONTWAIT',64,create=True),self.assertRaises(ValueError):obj.qualify()


class ClientSequence(unittest.TestCase):
    def client(self):
        obj=object.__new__(s.Client);obj.binding=B;obj.ready=None;obj.ended=False;obj.socket=Mock()
        record=f.child();record['context']['pid']=os.getpid()
        return obj,record

    def test_ready_never_waits_for_provider_ack(self):
        obj,record=self.client()
        with patch.object(s.time,'monotonic',return_value=100),patch.object(s,'packet') as send,patch.object(s,'receive') as receive:
            obj.emit({'phase':'READY','observation':record})
        send.assert_called_once();receive.assert_not_called();self.assertIsNotNone(obj.ready)

    def test_end_requires_both_exact_provider_acknowledgments(self):
        obj,record=self.client()
        with patch.object(s.time,'monotonic',return_value=100),patch.object(s,'packet'):
            obj.emit({'phase':'READY','observation':record})
        replies=[{'phase':p,'binding':B,'posted':True} for p in ('READY','END')]
        with patch.object(s.time,'monotonic',return_value=130),patch.object(s,'packet') as send,patch.object(s,'receive',side_effect=replies):
            obj.emit({'phase':'END','observation':record})
        send.assert_called_once();self.assertTrue(obj.ended)

    def test_missing_ready_ack_prevents_end_post(self):
        obj,record=self.client()
        with patch.object(s.time,'monotonic',return_value=100),patch.object(s,'packet'):
            obj.emit({'phase':'READY','observation':record})
        with patch.object(s.time,'monotonic',return_value=130),patch.object(s,'packet') as send,patch.object(s,'receive',return_value={}),self.assertRaises(ValueError):
            obj.emit({'phase':'END','observation':record})
        send.assert_not_called();self.assertFalse(obj.ended)


class Wiring(unittest.TestCase):
    def setUp(self):
        self.flow=yaml.load((ROOT/'.github/workflows/proof6-writer.yml').read_bytes(),Loader=yaml.BaseLoader)
        self.normal=self.flow['jobs']['writer'];self.d04=self.flow['jobs']['d04_writer']

    def test_exact_permissions_and_exclusive_jobs(self):
        self.assertEqual(set(self.flow['jobs']),{'signal_setup','writer','d04_writer'})
        self.assertEqual(self.flow['permissions'],{'contents':'read','actions':'read'})
        self.assertEqual(self.normal['permissions'],self.flow['permissions'])
        self.assertEqual(self.d04['permissions'],{'statuses':'write'})
        self.assertEqual(self.normal['if'].split("result == 'skipped') && ",1)[1].replace("!= 'D04_CONNECTIVITY_OUTAGE'","== 'D04_CONNECTIVITY_OUTAGE'"),self.d04['if'])
        self.assertEqual(self.flow['concurrency'],{'group':'proof6-authority-writer-r3','cancel-in-progress':'false'})

    def test_exact_token_delivery(self):
        execute=lambda job:next(x for x in job['steps'] if x.get('id')=='execute')
        self.assertEqual(execute(self.normal)['env']['GH_TOKEN'],'${{ github.token }}')
        self.assertEqual(execute(self.normal)['env']['PROOF6_D03_JOB_TOKEN'],'${{ github.token }}')
        for slot in ('GH_TOKEN','PROOF6_D03_JOB_TOKEN',s.TOKEN_SLOT):self.assertNotIn(slot,execute(self.d04)['env'])
        steps=self.d04['steps'];start=next(x for x in steps if x.get('id')=='d04-signal-start')
        self.assertEqual(start['env'],{s.TOKEN_SLOT:'${{ github.token }}'})
        self.assertLess(steps.index(start),next(i for i,x in enumerate(steps) if x.get('id')=='app-token'))
        self.assertNotIn('PROOF6_APP',start['run']);self.assertNotIn('${{',start['run'])
        self.assertEqual(execute(self.d04)['env']['PROOF6_APP_TOKEN'],'${{ steps.app-token.outputs.token }}')

    def test_no_new_action_secret_or_input(self):
        self.assertEqual(set(self.flow['on']),{'workflow_dispatch'})
        self.assertEqual(set(self.flow['on']['workflow_dispatch']['inputs']),{'proposal','proof_operation'})
        actions={x['uses'] for job in self.flow['jobs'].values() for x in job['steps'] if 'uses' in x}
        self.assertEqual(actions,{'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1'})

    def test_120_caps_and_always_cleanup(self):
        self.assertEqual(self.d04['steps'][-1]['if'],'always()')
        source=(ROOT/'.github/workflows/proof6-writer.yml').read_text()
        self.assertIn('wait "$native"',source);self.assertIn('reaped.exit',source)
        self.assertIn('/usr/bin/timeout --signal=KILL 120s',source)
        self.assertEqual(prior.module.outage.WINDOW_SECONDS,30)
        self.assertEqual(prior.module.outage.MAX_SECONDS,120)

    def test_new_read_wiring_does_not_substitute_d03_token(self):
        source=inspect.getsource(ar.get)
        self.assertIn("os.environ['GH_TOKEN']",source)
        self.assertIn("os.environ.get('GITHUB_JOB') == 'd04_writer'",source)
        self.assertIn('/collaborators/peaklinesoftware/permission',source)
        self.assertNotIn('PROOF6_D03_JOB_TOKEN',source)

    def test_fixed_endpoint_context_and_no_ref_mutation(self):
        source=inspect.getsource(s.status_request)
        self.assertNotIn('/git/',source);self.assertNotIn('/contents/',source)
        self.assertNotIn('PATCH',source);self.assertNotIn('DELETE',source)
        self.assertNotIn('PUT',source);self.assertIn('timeout=5',source)
        self.assertEqual(list(inspect.signature(s.serve).parameters),[])

    def test_plan_requires_live_patch_and_end(self):
        plan,_=prior.module.pc.plan()
        self.assertEqual(len(plan['cases']),72)
        self.assertTrue(all(x['disposition']=='FRESH' for x in plan['cases']))
        self.assertEqual(plan['accounting']['inherited'],0)
        self.assertEqual(plan['accounting']['NOT_APPLICABLE'],0)
        for word in ('provider READY','in_progress','ordinary authority PATCH','before actual END','helper reaping'):
            self.assertIn(word,plan['workflow_runs']['F4']['purpose'])
        self.assertIn('independent disposition required before freeze',plan['d04_signal']['verification_limit'])

    def test_no_authority_consumer(self):
        for name in ('writer.py','journal.py','admission.py','reconcile.py','sibling_canary.py'):
            source=(ROOT/'proofs/proof6'/name).read_text()
            self.assertNotIn('d04_signal',source)
            self.assertNotIn('/statuses',source)
        for path in ('proofs/proof1/replay.py','proofs/proof2/gate.py'):
            self.assertNotIn('d04_signal',(ROOT/path).read_text())


class Ordering(prior.module.Admission):
    # Exercise the same production D04 admission with targeted Client outcomes.
    def run_d04(self,*args,**kwargs):
        return prior._previous(self,*args,**kwargs)

    def setUp(self):
        super().setUp()
        self.signal_patch=patch.object(ar.d04_signal,'Client',return_value=Mock(ended=True))
        self.start=self.signal_patch.start();self.addCleanup(self.signal_patch.stop)

    def test_helper_failure_leaves_unconsumed(self):
        before=copy.deepcopy(self.g.refs);self.start.side_effect=ValueError('OFFLINE_START_FAILURE')
        code,result,_,actual,_=self.run_d04()
        self.assertEqual(code,1);self.assertEqual(result['result'],'PRECONDITION_BLOCKED')
        self.assertEqual(self.g.refs,before);actual.assert_not_called()
        self.assertEqual(self.g.journal_sends,0)

    def test_readiness_between_prerequisite_and_consume(self):
        order=[]
        def ready():
            self.assertEqual(order,['prerequisite']);self.assertEqual(self.g.journal_sends,0)
            order.append('signal');return Mock(ended=True)
        self.start.side_effect=ready
        def prerequisite():order.append('prerequisite');return f.prerequisite()
        def actual(emit):
            self.assertEqual(order,['prerequisite','signal']);self.assertEqual(self.g.journal_sends,1)
            return dict(result='OUTAGE_COMPLETED',update_attempted=False,remote_outcome='not_attempted')
        self.assertEqual(self.run_d04(prerequisite,actual)[0],0)

    def test_journal_move_during_readiness_blocks(self):
        # Journal head must be captured BEFORE readiness, not after it.
        original=prior.module.j.Journal.read
        heads=[]
        def ready():
            heads.append(self.g.refs[prior.module.j.REF])
            self.g.refs[prior.module.j.REF]='f'*40
            return Mock(ended=True)
        self.start.side_effect=ready
        code,result,_,actual,_=self.run_d04()
        self.assertEqual(code,1);self.assertEqual(result['result'],'PRECONDITION_BLOCKED')
        self.assertEqual(self.g.journal_sends,0);actual.assert_not_called()

    def test_postconsumption_signal_failure_never_refunds(self):
        def actual(emit):raise ValueError('OFFLINE_POST_FAILURE')
        code,result,_,_,_=self.run_d04(actual=actual)
        self.assertEqual(code,1);self.assertEqual(result['result'],'D04_FAILED_CONSUMED')
        self.assertEqual(self.g.journal_sends,1);self.assertEqual(self.g.authority_sends,0)
        self.assertEqual(self.run_d04()[1]['result'],'PRECONDITION_BLOCKED')
        self.assertEqual(self.g.journal_sends,1)

    def test_helper_dies_after_handshake_before_consumption(self):
        self.start.return_value.qualify.side_effect=ValueError('OFFLINE_DEAD_HELPER')
        code,result,_,actual,_=self.run_d04()
        self.assertEqual(code,1);self.assertEqual(result['result'],'PRECONDITION_BLOCKED')
        self.assertEqual(self.g.journal_sends,0);actual.assert_not_called()


if __name__=='__main__':
    with patch.object(socket,'socket',side_effect=AssertionError('OFFLINE_ONLY')):
        unittest.main(verbosity=2)
