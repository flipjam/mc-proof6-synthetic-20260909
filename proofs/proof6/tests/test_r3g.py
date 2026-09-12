"""Offline D04 counterexamples; no live unshare, GitHub request or acceptance."""
import ast
import contextlib
import copy
import inspect
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

import d04_fixtures as f
cap, pre = f.cap, f.pre
import r3g_regression as retained
e = retained.support.legacy
ar, j, w, pc, outage = e.ar, e.j, e.w, e.pc, e.outage
ROOT = retained.support.ROOT


class Predicate(unittest.TestCase):
    def exercise(self, v4='', v6=None, interfaces=None, netns='net:[4026532219]',
                 rc=0, number=0, libc_error=None, connection=None, read_error=None):
        libc = Mock(); libc.unshare.return_value = rc
        events = []
        def read(path):
            if read_error and path == read_error[0]:
                raise read_error[1]
            return {'/proc/net/route':v4,'/proc/net/ipv6_route':f.route6()*2 if v6 is None else v6}[path]
        with patch.object(cap,'context',return_value=f.context()), \
             patch.object(cap,'netns',return_value=netns), \
             patch.object(cap,'read',side_effect=read), \
             patch.object(cap.ctypes,'CDLL',side_effect=libc_error,return_value=libc), \
             patch.object(cap.ctypes,'get_errno',return_value=number), \
             patch.object(cap.socket,'if_nameindex',return_value=interfaces or [(1,'lo')]), \
             patch.object(cap.socket,'create_connection',side_effect=connection or socket.gaierror(-3,'DO_NOT_LEAK')):
            result = cap.isolate(lambda record:events.append(copy.deepcopy(record)))
        cap.validate_record(result)
        self.assertNotIn('DO_NOT_LEAK',json.dumps(result))
        return result, events, libc

    def fail(self, stage, **kwargs):
        result, _, _ = self.exercise(**kwargs)
        self.assertFalse(result['qualified']); self.assertEqual(result['stage'],stage)
        return result

    def test_hosted_empty_route_observations(self):
        retained_record = json.loads((ROOT/'proofs/proof6/tests/r3g-evidence/diagnostic-record.json').read_bytes())
        self.assertEqual(retained_record['ipv4_route_line_count'],0)
        self.assertEqual(retained_record['interfaces'],['lo'])
        self.assertEqual(retained_record['ipv6'],{'entry_count':2,'interfaces':['lo']})
        result, _, libc = self.exercise()
        self.assertTrue(result['qualified']); self.assertFalse(result['acceptance_credit'])
        self.assertTrue(result['ipv4']['read_success']); self.assertFalse(result['ipv4']['header_present'])
        self.assertEqual(result['context']['kernel'],retained_record['kernel'])
        self.assertEqual(result['unshare'],retained_record['unshare'])
        self.assertEqual(result['netns_after'],retained_record['netns_after'])
        libc.unshare.assert_called_once_with(0x40000000)
        # IPv6 raw rows were not retained by #45. These are explicit authored
        # reject-route fixtures matching its summary, not recovered raw bytes.

    def test_header_only(self):
        result,_,_ = self.exercise(v4='\t'.join(cap.HEADER)+'\n')
        self.assertTrue(result['qualified']); self.assertTrue(result['ipv4']['header_valid'])

    def test_real_ipv4_route(self):
        header='\t'.join(cap.HEADER)+'\n'
        for line in ('eth0 00000000 0100000A 0003 0 0 100 00000000 0 0 0\n',
                     'lo 0000007F 00000000 0001 0 0 0 000000FF 0 0 0\n'):
            result=self.fail('IPV4_ROUTES_FAILED',v4=header+line)
            self.assertTrue(result['ipv4']['valid']); self.assertEqual(result['ipv4']['entry_count'],1)

    def test_malformed_ipv4(self):
        for raw in ('\n',' ','Iface bad\n','garbage','\x00',' '.join(cap.HEADER)+'\n\n',
                    ' '.join(cap.HEADER)+'\nlo garbage\n'):
            with self.subTest(raw=repr(raw)):
                result=self.fail('IPV4_ROUTES_FAILED',v4=raw)
                self.assertFalse(result['ipv4']['valid'])

    def test_unreadable_ipv4(self):
        result=self.fail('IPV4_ROUTES_FAILED',read_error=('/proc/net/route',PermissionError(13,'DO_NOT_LEAK')))
        self.assertEqual(result['ipv4'],{'read_success':False})

    def test_unreadable_ipv6(self):
        self.fail('IPV6_ROUTES_FAILED',read_error=('/proc/net/ipv6_route',FileNotFoundError(2,'DO_NOT_LEAK')))

    def test_non_loopback_interface(self):
        self.fail('INTERFACES_FAILED',interfaces=[(1,'lo'),(2,'eth0')])

    def test_namespace_unchanged(self):
        self.fail('NETNS_FAILED',netns='net:[4026531833]')

    def test_ipv6_loopback_and_multicast_on_lo(self):
        for route in ('',f.route6(dest=cap.LOOPBACK,prefix='80',flags='00000001'),
                      f.route6(dest='ff'+'0'*30,prefix='08',flags='00000001')):
            self.assertTrue(self.exercise(v6=route)[0]['qualified'])

    def test_ipv6_external_interface(self):
        self.fail('IPV6_ROUTES_FAILED',v6=f.route6(interface='eth0'))

    def test_ipv6_external_destination_on_lo(self):
        self.fail('IPV6_ROUTES_FAILED',v6=f.route6(dest='2001'+'0'*28,prefix='40'))

    def test_ipv6_source_route_external(self):
        self.fail('IPV6_ROUTES_FAILED',v6=f.route6(src='2001'+'0'*28,src_prefix='40'))

    def test_ipv6_gateway_or_next_hop(self):
        for route in (f.route6(hop=cap.LOOPBACK),f.route6(flags='00200202')):
            self.fail('IPV6_ROUTES_FAILED',v6=route)

    def test_ipv6_default_without_reject_flag(self):
        self.fail('IPV6_ROUTES_FAILED',v6=f.route6(flags='00000001'))

    def test_ipv6_malformed_and_bounds(self):
        for route in ('\n','invalid\n',f.route6(prefix='ff'),f.route6()*257,f.route6().replace('00000001','zzzzzzzz')):
            self.fail('IPV6_ROUTES_FAILED',v6=route)

    def test_connectivity_still_live(self):
        with patch.object(cap.socket,'create_connection',return_value=Mock()):
            # exercise owns its socket patch; use a callable successful result.
            result,_,_ = self.exercise(connection=lambda *a,**k:Mock())
        self.assertEqual(result['stage'],'CONNECTIVITY_STILL_LIVE'); self.assertFalse(result['qualified'])

    def test_dns_failure_alone_insufficient(self):
        self.fail('NETNS_FAILED',netns=f.context()['netns'])
        self.fail('INTERFACES_FAILED',interfaces=[(1,'eth0')])

    def test_unshare_errno_retained_and_cleared(self):
        with patch.object(cap.ctypes,'set_errno') as cleared:
            result=self.fail('UNSHARE_FAILED',rc=-1,number=1)
        cleared.assert_called_once_with(0)
        self.assertEqual(result['unshare'],dict(return_code=-1,errno=1,errno_name='EPERM'))

    def test_libc_load_failure(self):
        self.fail('LIBC_FAILED',libc_error=OSError(2,'DO_NOT_LEAK'))

    def test_libc_symbol_failure(self):
        libc=Mock(); del libc.unshare
        with patch.object(cap,'context',return_value=f.context()),patch.object(cap.ctypes,'CDLL',return_value=libc):
            result=cap.isolate()
        self.assertEqual(result['stage'],'LIBC_FAILED')
        self.assertEqual(result['exception']['type'],'AttributeError')

    def test_unknown_observation_error(self):
        result=self.fail('IPV4_ROUTES_FAILED',read_error=('/proc/net/route',RuntimeError('DO_NOT_LEAK')))
        self.assertEqual(result['exception']['type'],'UNKNOWN_EXCEPTION')

    def test_unexpected_connect_error_cannot_qualify(self):
        for error in (PermissionError(13,'DO_NOT_LEAK'), OSError(9,'DO_NOT_LEAK'),
                      socket.gaierror(-10,'DO_NOT_LEAK'), RuntimeError('DO_NOT_LEAK')):
            self.fail('CONNECTIVITY_FAILED',connection=error)

    def test_stale_errno_cannot_qualify(self):
        self.fail('UNSHARE_FAILED',rc=0,number=1)

    def test_context_failure(self):
        with patch.object(cap,'context',side_effect=RuntimeError('DO_NOT_LEAK')):
            result=cap.isolate()
        self.assertEqual(result['stage'],'CONTEXT_FAILED'); self.assertNotIn('DO_NOT_LEAK',json.dumps(result))

    def test_fixed_stage_sequence(self):
        result, events, _ = self.exercise()
        self.assertEqual([r['phase'] for r in events],['LIBC_OK','UNSHARE_OK','NETNS_OK','INTERFACES_OK',
                          'IPV4_ROUTES_OK','IPV6_ROUTES_OK','CONNECTIVITY_ISOLATED'])
        self.assertTrue(result['qualified'])

    def test_bounded_read_and_non_ascii(self):
        for data in (b'a'*65537,b'\xff'):
            with patch('builtins.open',return_value=contextlib.nullcontext(io.BytesIO(data))),self.assertRaises((ValueError,UnicodeDecodeError)):
                cap.read('/proc/net/route')

    def test_context_allowlist(self):
        raw={'/proc/self/status':'CapEff:\t000001ffffffffff\nSeccomp:\t0\n',
             '/proc/self/attr/current':'unconfined\n'}
        with patch.object(cap,'read',side_effect=raw.__getitem__),patch.object(cap,'netns',return_value=f.context()['netns']), \
             patch.object(os,'geteuid',return_value=0,create=True),patch.object(os,'uname',return_value=Mock(release='kernel'),create=True), \
             patch.dict(os.environ,{'GH_TOKEN':'DO_NOT_LEAK','PROOF6_APP_TOKEN':'DO_NOT_LEAK'}):
            result=cap.context()
        self.assertNotIn('DO_NOT_LEAK',json.dumps(result)); self.assertEqual(set(result['runner']),set(cap.RUNNER_KEYS))


class Prerequisite(unittest.TestCase):
    def exercise(self, child=None, rc=0, contexts=None, raw=None):
        proc=Mock(); proc.returncode=rc; proc.pid=12345
        proc.communicate.return_value=(json.dumps(child or f.child()).encode() if raw is None else raw,None)
        proc.__enter__=Mock(return_value=proc);proc.__exit__=Mock(return_value=None)
        with patch.object(cap,'context',side_effect=contexts or [f.context(),f.context()]), \
             patch.object(pre.subprocess,'Popen',return_value=proc) as popen:
            result=pre.run()
        return result,popen,proc

    def test_setup_pass_receipt(self):
        result,_,_=self.exercise()
        self.assertTrue(result['qualified']); self.assertFalse(result['acceptance_credit'])
        self.assertEqual(pre.setup_qualification(json.dumps(result)),result)

    def test_child_fail_blocks(self):
        child=f.child();child.update(qualified=False,stage='UNSHARE_FAILED')
        child['unshare']={'return_code':-1,'errno':1,'errno_name':'EPERM'}
        result,_,_=self.exercise(child=child,rc=1)
        self.assertFalse(result['qualified']);self.assertEqual(result['child']['unshare']['errno'],1)
        with self.assertRaises(ValueError):pre.setup_qualification(json.dumps(result))

    def test_context_mismatch_all_fields(self):
        for key in pre.CONTEXT_KEYS:
            child=f.child()
            changes={'euid':1,'kernel':'other','cap_eff':'0000000000000000','cap_sys_admin':False,
                     'seccomp':2,'lsm':'other','netns':'net:[999]', 'runner':dict(child['context']['runner'],ImageVersion='other')}
            child['context'][key]=changes[key]
            with self.subTest(key=key):self.assertFalse(self.exercise(child=child)[0]['qualified'])

    def test_same_pid_is_not_child(self):
        child=f.child();child['context']['pid']=os.getpid()
        self.assertFalse(self.exercise(child=child)[0]['qualified'])

    def test_parent_netns_changed_blocks(self):
        after=f.context();after['netns']='net:[999]'
        self.assertFalse(self.exercise(contexts=[f.context(),after])[0]['qualified'])

    def test_parent_lacks_capability_blocks_before_spawn(self):
        parent=f.context();parent['cap_sys_admin']=False
        result,popen,_=self.exercise(contexts=[parent])
        self.assertFalse(result['qualified']);popen.assert_not_called()

    def test_credentials_scrubbed_and_descriptors_closed(self):
        with patch.dict(os.environ,{'GH_TOKEN':'DO_NOT_LEAK','PROOF6_APP_TOKEN':'DO_NOT_LEAK','PYTHONPATH':'DO_NOT_LEAK'}):
            result,popen,proc=self.exercise()
        call=popen.call_args
        self.assertEqual(call.args[0][:7],['/usr/bin/timeout','--foreground','--signal=KILL','20s','/usr/bin/python3','-I','-B'])
        self.assertEqual(set(call.kwargs['env']),{'PATH','LANG',*cap.RUNNER_KEYS})
        self.assertTrue(call.kwargs['close_fds']);self.assertFalse(call.kwargs['start_new_session'])
        self.assertEqual(call.kwargs['stdin'],subprocess.DEVNULL)
        self.assertEqual(call.kwargs['stderr'],subprocess.DEVNULL)
        self.assertNotIn('DO_NOT_LEAK',repr(call));proc.communicate.assert_called_once_with()
        self.assertTrue(result['child_reaped']);proc.__exit__.assert_called_once()

    def test_native_failure_overrides_child_pass(self):
        result,_,_=self.exercise(rc=137)
        self.assertFalse(result['qualified']);self.assertEqual(result['supervisor_exit'],137)

    def test_native_timeout_reaped_and_no_session_escape(self):
        result,popen,proc=self.exercise(rc=137,raw=b'')
        self.assertTrue(result['child_reaped']);self.assertFalse(result['qualified'])
        self.assertIn('--foreground',popen.call_args.args[0])
        self.assertFalse(popen.call_args.kwargs['start_new_session'])
        proc.__exit__.assert_called_once()

    def test_no_caller_parameters_or_forbidden_imports(self):
        self.assertEqual(list(inspect.signature(pre.run).parameters),[])
        for module in (cap,pre):
            source=inspect.getsource(module);tree=ast.parse(source)
            imports=[n.module for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)]
            imports += [a.name for n in ast.walk(tree) if isinstance(n,ast.Import) for a in n.names]
            self.assertFalse(set(imports)&{'writer','journal','proof_control','gate','urllib','http'})
            self.assertNotIn('api.github.com/',source)

    def test_leaf_arguments_rejected_without_isolation(self):
        for name in ('d04_capability.py','d04_prerequisite.py'):
            out=subprocess.run([sys.executable,'-I','-B',str(ROOT/'proofs/proof6'/name),'caller-command'],capture_output=True,timeout=5)
            self.assertEqual(out.returncode,1);self.assertEqual(json.loads(out.stdout)['stage'],'INPUT_REJECTED')

    def test_extra_fields_and_secret_text_not_relayed(self):
        for place in ('root','child_exception','context'):
            child=f.child()
            if place=='root':child['secret']='DO_NOT_LEAK'
            elif place=='child_exception':child['exception']={'type':'DO_NOT_LEAK','errno':None}
            else:child['context']['secret']='DO_NOT_LEAK'
            result,_,_=self.exercise(child=child)
            self.assertFalse(result['qualified']);self.assertNotIn('DO_NOT_LEAK',json.dumps(result))

    def test_malformed_oversize_and_duplicate_stdout(self):
        for raw in (b'no-json',b'{}\n{}',b'a'*16385):
            self.assertFalse(self.exercise(raw=raw)[0]['qualified'])

    def test_missing_setup_qualification(self):
        for raw in ('','{}','null',json.dumps(dict(f.prerequisite(),qualified=False))):
            with self.assertRaises((ValueError,KeyError,TypeError)):pre.setup_qualification(raw)


class Admission(unittest.TestCase):
    def setUp(self):
        self.g=e.Git();self.obj=e.writer(self.g,50,pc.OUTAGE)

    def run_d04(self, prerequisite=None, actual=None):
        env=e.Bootstrap().context();env.update(PROOF6_FROZEN_MANIFEST=json.dumps(self.obj._manifest),
            GITHUB_ACTOR=e.CALLER['login'],GITHUB_ACTOR_ID=str(e.CALLER['id']),GITHUB_TRIGGERING_ACTOR=e.CALLER['login'])
        event=json.dumps({'inputs':{'proof_operation':pc.OUTAGE}})
        output=io.StringIO()
        with patch.dict(os.environ,env,clear=True),patch.object(Path,'read_text',return_value=event), \
             patch.object(ar,'guard'),patch.object(pc,'qualify',return_value=e.CALLER), \
             patch.object(ar,'_Writer',return_value=self.obj), \
             patch.object(ar,'get',side_effect=lambda path:self.g.api('offline-token','GET','/'+path)), \
             patch.object(pre,'run',side_effect=prerequisite or (lambda:f.prerequisite())) as helper, \
             patch.object(outage,'isolate_runtime',side_effect=actual or (lambda emit:dict(result='OUTAGE_COMPLETED',update_attempted=False,remote_outcome='not_attempted'))) as isolate, \
             patch.object(ar.dia,'blocked') as generic,contextlib.redirect_stdout(output):
            code=ar.execute()
        records=[json.loads(line.removeprefix('PROOF6_RESULT ')) for line in output.getvalue().splitlines() if line.startswith('PROOF6_RESULT ')]
        return code,records[-1],helper,isolate,generic

    def test_pass_precedes_consumption_and_actual_isolation(self):
        order=[]
        def helper():
            self.assertEqual(self.g.journal_sends,0);order.append('prerequisite');return f.prerequisite()
        def actual(emit):
            self.assertEqual(self.g.row(self.g.refs[j.REF])['type'],'CONSUMED')
            self.assertEqual(self.obj._installation_token,'');self.assertEqual(self.g.authority_sends,0)
            order.append('actual');return dict(result='OUTAGE_COMPLETED',update_attempted=False,remote_outcome='not_attempted')
        code,_,_,_,_=self.run_d04(helper,actual)
        self.assertEqual(code,0);self.assertEqual(order,['prerequisite','actual']);self.assertEqual(self.g.journal_sends,1)

    def test_failed_prerequisite_no_consumption_or_authority(self):
        before=copy.deepcopy(self.g.refs)
        failed=dict(f.prerequisite(),qualified=False,stage='CHILD_QUALIFICATION_BLOCKED')
        code,result,_,actual,generic=self.run_d04(lambda:failed)
        self.assertEqual(code,1);self.assertEqual(result['result'],'PRECONDITION_BLOCKED')
        self.assertEqual(self.g.refs,before);self.assertEqual((self.g.journal_sends,self.g.authority_sends),(0,0))
        self.assertFalse(any(c[1] in ('POST','PATCH','PUT','DELETE') for c in self.g.calls))
        actual.assert_not_called();generic.assert_not_called()

    def test_unspent_can_be_newly_admitted(self):
        self.run_d04(lambda:dict(f.prerequisite(),qualified=False))
        self.obj=e.writer(self.g,51,pc.OUTAGE)
        self.assertEqual(self.run_d04()[0],0);self.assertEqual(self.g.journal_sends,1)

    def test_actual_failure_consumed_without_refund(self):
        failed=f.child();failed.update(qualified=False,stage='UNSHARE_FAILED')
        code,result,_,_,generic=self.run_d04(actual=lambda emit:(_ for _ in ()).throw(cap.CapabilityError(failed)))
        self.assertEqual(code,1);self.assertEqual(result['result'],'D04_FAILED_CONSUMED')
        self.assertEqual(result['d04_diagnostic']['stage'],'UNSHARE_FAILED');generic.assert_not_called()
        self.obj=e.writer(self.g,51,pc.OUTAGE)
        _,_,helper,actual,_=self.run_d04()
        helper.assert_not_called();actual.assert_not_called();self.assertEqual(self.g.journal_sends,1)

    def test_unresolved_recovery_cannot_append_before_prerequisite(self):
        fix=retained.original.Fixture();fix.setUp()
        # Use the accepted production journal setup helper, without sending.
        journal,p,c=retained.support.begin_valid(fix);journal.arm(p);fix.g.refs[w.REF]=c
        self.g=fix.g;self.obj=e.writer(self.g,50,pc.OUTAGE);before=self.g.journal_sends
        _,result,helper,actual,_=self.run_d04()
        self.assertEqual(result['result'],'PRECONDITION_BLOCKED');self.assertEqual(self.g.journal_sends,before)
        helper.assert_not_called();actual.assert_not_called();self.assertEqual(self.g.authority_sends,0)

    def test_context_mismatch_blocks_before_consumption(self):
        failed=dict(f.prerequisite(),qualified=False,stage='CONTEXT_MATCH_BLOCKED')
        _,result,_,actual,_=self.run_d04(lambda:failed)
        self.assertEqual(result['result'],'PRECONDITION_BLOCKED');actual.assert_not_called();self.assertEqual(self.g.journal_sends,0)

    def test_journal_changes_during_child_blocks(self):
        def helper():
            journal=j.Journal(self.obj)
            journal.consume(journal.operation_binding(w._canonical(e.PLAN['infrastructure']),pc.OUTAGE))
            return f.prerequisite()
        _,result,_,actual,_=self.run_d04(helper)
        self.assertEqual(result['result'],'PRECONDITION_BLOCKED');actual.assert_not_called()
        self.assertEqual(self.g.journal_sends,1) # simulated competing append only

    def test_ambiguous_consumption_never_claims_unspent(self):
        with patch.object(j.Journal,'consume',side_effect=OSError('DO_NOT_LEAK')):
            _,result,_,actual,_=self.run_d04()
        self.assertEqual(result['result'],'D04_CONSUMPTION_UNCONFIRMED');actual.assert_not_called()
        self.assertNotIn('DO_NOT_LEAK',json.dumps(result))

    def test_setup_failure_blocks_before_app_diagnostic(self):
        original=e.Bootstrap.context
        def missing(test):
            env=original(test);env.pop('PROOF6_D04_SETUP_QUALIFICATION');return env
        with patch.object(e.Bootstrap,'context',missing):
            code,result,calls=e.Bootstrap().route()
        self.assertEqual((code,result,calls),(1,None,0))


class ActualProcess(unittest.TestCase):
    def test_shared_actual_process_structure(self):
        main=inspect.getsource(ar.main);source=inspect.getsource(outage.isolate_runtime)
        self.assertLess(main.index('d04_prerequisite.run()'),main.index('claim = journal.consume'))
        self.assertLess(main.index('claim = journal.consume'),main.index('result = isolate_runtime'))
        self.assertIn('capability.isolate(emit)',source);self.assertIn('capability.recheck(record, emit)',source)
        for forbidden in ('Popen','subprocess','fork(', 'setns(', '_patch('):self.assertNotIn(forbidden,source)
        self.assertIn('libc.unshare(CLONE_NEWNET)',inspect.getsource(cap.isolate))
        self.assertIn("'d04_capability.py'",inspect.getsource(pre.run))

    def test_actual_pid_and_30_second_window(self):
        clock=[75.0];events=[];calls=[]
        def isolate(emit):calls.append(os.getpid());return f.child()
        with patch.object(outage.time,'monotonic',side_effect=lambda:clock[0]), \
             patch.object(outage.time,'sleep',side_effect=lambda n:clock.__setitem__(0,clock[0]+n)), \
             patch.object(cap,'isolate',side_effect=isolate),patch.object(cap,'recheck',side_effect=lambda r,e:r) as end:
            result=outage.isolate_runtime(lambda r:events.append(copy.deepcopy(r)))
        self.assertEqual(clock[0],105.0);self.assertEqual(calls,[os.getpid()])
        self.assertEqual([r['phase'] for r in events],['START','READY','END'])
        self.assertEqual({r['pid'] for r in events},{os.getpid()});end.assert_called_once()
        self.assertEqual(result['result'],'OUTAGE_COMPLETED');self.assertEqual((outage.WINDOW_SECONDS,outage.MAX_SECONDS),(30,120))

    def test_actual_failure_has_no_ready_or_end(self):
        events=[];record=dict(f.child(),qualified=False,stage='UNSHARE_FAILED')
        with patch.object(cap,'isolate',return_value=record),self.assertRaises(cap.CapabilityError):
            outage.isolate_runtime(events.append)
        self.assertEqual([r['phase'] for r in events],['START'])

    def test_end_rechecks_and_failure_cannot_complete(self):
        events=[]
        with patch.object(cap,'isolate',return_value=f.child()), \
             patch.object(outage.time,'monotonic',side_effect=[0,0,30]), \
             patch.object(cap,'recheck',side_effect=cap.CapabilityError(dict(f.child(),qualified=False))),self.assertRaises(cap.CapabilityError):
            outage.isolate_runtime(events.append)
        self.assertEqual([r['phase'] for r in events],['START','READY'])

    def test_end_production_observation_failure(self):
        record=f.child()
        with patch.object(cap,'netns',return_value=f.context()['netns']),self.assertRaises(cap.CapabilityError):
            cap.recheck(record)
        self.assertEqual(record['stage'],'NETNS_FAILED')

    def test_end_success_preserves_valid_terminal_schema(self):
        record=f.child()
        with patch.object(cap,'netns',return_value=record['netns_after']), \
             patch.object(cap.socket,'if_nameindex',return_value=[(1,'lo')]), \
             patch.object(cap,'read',side_effect=lambda p:'' if p.endswith('/route') else f.route6()), \
             patch.object(cap.socket,'create_connection',side_effect=socket.gaierror(-3,'DO_NOT_LEAK')):
            cap.recheck(record)
        self.assertEqual(record['stage'],'QUALIFIED');cap.validate_record(record)

    def test_end_unreadable_route_does_not_retain_old_read_success(self):
        for path,stage,family in [('/proc/net/route','IPV4_ROUTES_FAILED','ipv4'),
                                  ('/proc/net/ipv6_route','IPV6_ROUTES_FAILED','ipv6')]:
            record=f.child()
            def read(p):
                if p==path:raise PermissionError(13,'DO_NOT_LEAK')
                return ''
            with patch.object(cap,'netns',return_value=record['netns_after']), \
                 patch.object(cap.socket,'if_nameindex',return_value=[(1,'lo')]), \
                 patch.object(cap,'read',side_effect=read),self.assertRaises(cap.CapabilityError):
                cap.recheck(record)
            self.assertEqual(record['stage'],stage)
            self.assertEqual(record[family],{'read_success':False});cap.validate_record(record)

    def test_helper_pass_cannot_emit_ready(self):
        source=inspect.getsource(pre)
        self.assertNotIn("'READY'",source);self.assertNotIn('OUTAGE_COMPLETED',source)
        self.assertFalse(f.prerequisite()['acceptance_credit'])

    def test_native_supervisor_success_and_failure(self):
        script=e.Corrections().workflow_script()
        for rc in (0,1,137):
            out=subprocess.run(['wsl','-d','Ubuntu-22.04','--','bash','-s'],
                input=f'sudo() {{ return {rc}; }}\nexport PROOF6_OPERATION=D04_CONNECTIVITY_OUTAGE\n'.encode()+script.encode(),capture_output=True,timeout=30)
            self.assertEqual(out.returncode,rc,out.stderr)
            self.assertEqual(b'PROOF6_D04_NATIVE_DEADLINE_COMPLETED' in out.stdout,rc==0)
            self.assertEqual(b'SUPERVISOR_COMPLETED' in out.stdout,rc==0)
            if rc:self.assertIn(b'SUPERVISOR_FAILED',out.stdout)

    def test_workflow_setup_order_and_no_extra_input(self):
        workflow=(ROOT/'.github/workflows/proof6-writer.yml').read_text()
        self.assertLess(workflow.index('id: d04-setup'),workflow.index('id: app-token'))
        self.assertIn("if: vars.PROOF6_FROZEN_MANIFEST == ''",workflow)
        self.assertIn('steps.d04-setup.outputs.qualification',workflow)
        self.assertIn('deadline=(/usr/bin/timeout --signal=KILL 120s)',workflow)
        self.assertIn('runs-on: ubuntu-24.04',workflow);self.assertIn('cancel-in-progress: false',workflow)
        self.assertEqual(len(list((ROOT/'.github/workflows').glob('*'))),1)
        for key in ('host','command','duration','predicate','namespace'):
            with self.assertRaises(ValueError):pc.request({key:'caller-value'})


class IdentityAndSchema(unittest.TestCase):
    def test_record_bounds_and_unknown_fields(self):
        for change in ({'secret':'DO_NOT_LEAK'},{'elapsed_seconds':float('nan')},{'qualified':1}):
            with self.assertRaises(ValueError):cap.validate_record(dict(f.child(),**change))
        self.assertLess(len(json.dumps(f.prerequisite())),32768)

    def test_false_qualification_conjunction(self):
        for key,value in (('netns_after',f.context()['netns']),('interfaces',['eth0']),('libc_loaded',False)):
            with self.assertRaises(ValueError):cap.validate_record(dict(f.child(),**{key:value}))

    def test_malformed_nested_qualification_cannot_pass(self):
        for family, key, value in [('ipv4','read_success',0),('ipv4','header_valid',True),
                                  ('unshare','errno',1),('connectivity','exception',None)]:
            record=f.child(); record[family][key]=value
            with self.assertRaises(ValueError):cap.validate_record(record)

    def test_setup_extra_data_rejected(self):
        with self.assertRaises(ValueError):pre.setup_qualification(json.dumps(dict(f.prerequisite(),secret='DO_NOT_LEAK')))

    def test_72_rows_and_budget_explicitly_mapped(self):
        plan,_=pc.plan();groups=set(plan['workflow_runs'])|set(plan['external_evidence_groups'])
        self.assertEqual(len(plan['cases']),72);self.assertEqual(len(plan['workflow_runs']),10)
        for row in plan['cases']:
            self.assertEqual(row['disposition'],'FRESH');self.assertTrue(set(row['evidence_groups'])<=groups)
        self.assertEqual(plan['accounting']['inherited'],0);self.assertEqual(plan['accounting']['NOT_APPLICABLE'],0)
        self.assertEqual(plan['d04_capability'],cap.POLICY);self.assertFalse(plan['diagnostic_provenance']['acceptance_credit'])

    def test_fresh_future_genesis(self):
        self.assertEqual(j.REF,'refs/heads/proof6-operation-journal-r3g')
        self.assertEqual(j.SCHEMA,'PROOF6_R3G_JOURNAL_V1')
        self.assertEqual(e.Git().row(e.Git().genesis)['type'],'GENESIS')
        plan,_=pc.plan();self.assertIn('journal_genesis_commit',plan['live_bindings_deferred'])

    def test_unchanged_safety_semantics_after_identity_normalization(self):
        base='704a32834981ce1ebcfc0f963abe25297b89f304'
        for name in ('writer.py','journal.py','app_probes.py','d03_job_token.py'):
            before=subprocess.check_output(['git','-C',str(ROOT),'show',base+':proofs/proof6/'+name])
            expected=before.replace(b'r3f',b'r3g').replace(b'R3F',b'R3G').replace(b'R3f',b'R3g')
            self.assertEqual((ROOT/'proofs/proof6'/name).read_bytes(),expected,name)
        for name in ('proofs/proof1/replay.py','proofs/proof2/gate.py','proofs/proof6/d03_rejection.py','proofs/proof6/sibling_canary.py'):
            self.assertEqual((ROOT/name).read_bytes(),subprocess.check_output(['git','-C',str(ROOT),'show',base+':'+name]))

    def test_all_prior_assertion_files_preserved(self):
        for name in ('legacy_r3e.py','legacy_reviewer_r3e.py','test_r3f.py','test_caller_types.py','regression.py','reviewer_regression.py'):
            self.assertEqual((ROOT/'proofs/proof6/tests'/name).read_bytes(),subprocess.check_output(['git','-C',str(ROOT),'show','704a32834981ce1ebcfc0f963abe25297b89f304:proofs/proof6/tests/'+name]))


if __name__ == '__main__':
    # Every capability syscall/connection is mocked. The only subprocesses are
    # argument rejection and harmless local supervisor fixtures.
    with patch.object(socket,'socket',side_effect=AssertionError('OFFLINE_ONLY')):
        unittest.main(verbosity=2)
