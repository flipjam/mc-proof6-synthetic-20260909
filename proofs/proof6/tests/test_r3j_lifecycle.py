"""Prospective D04 deadline/consumption and shared lifecycle admission tests."""
import contextlib
import copy
import io
import json
import socket
import unittest
from unittest.mock import Mock, patch
import r3j_prior as prior
import r3j_regression
from r3j_support import legacy as e
import journal as j
import journal_confirmation as diagnostic
import d04_signal as signal
import actions_runtime as ar
from test_r3j_confirmation import Rig


class D04(unittest.TestCase):
    def run_case(self, sequence, budget=55):
        fixture=prior.module.Admission();fixture.setUp()
        parent=fixture.g.refs[j.REF];api=fixture.g.api;child=[None];reads=[];order=[];clock=[100.0]
        client=Mock(ended=True,deadline=100.0+budget)
        client.socket.recv.side_effect=BlockingIOError
        real_qualify=signal.Client.qualify
        def qualify():
            order.append(('qualify',fixture.g.journal_sends))
            real_qualify(client)
        client.qualify.side_effect=qualify
        def provider(token,method,path,body=None):
            if method=='PATCH':
                value=api(token,method,path,body);child[0]=body['sha'];order.append(('PATCH',1));return value
            if child[0] and method=='GET' and path==j.BASE+'/git/ref/'+j.REF.removeprefix('refs/'):
                item=sequence[len(reads)] if len(reads)<len(sequence) else 'C'
                reads.append(item);order.append(('read',item))
                return {'ref':j.REF,'object':{'type':'commit','sha':{'C':child[0],'P':parent,'S':'b'*40}[item]}}
            return api(token,method,path,body)
        fixture.obj._call=provider
        def prerequisite():
            self.assertEqual(fixture.g.journal_sends,0)
            order.append(('prerequisite',0));return prior.module.f.prerequisite()
        def actual(emit):
            self.assertEqual(fixture.obj._journal_confirmation['result'],'CONFIRMED')
            self.assertEqual(order[-1],('qualify',1))
            self.assertGreaterEqual(client.deadline-clock[0],50)
            order.append(('isolation',1))
            return {'result':'OUTAGE_COMPLETED','update_attempted':False,'remote_outcome':'not_attempted'}
        def wait(seconds):
            self.assertEqual(seconds,1);clock[0]+=seconds;order.append(('wait',1))
        with patch.object(signal,'Client',return_value=client),patch.object(signal.time,'monotonic',side_effect=lambda:clock[0]), \
                patch.object(j.time,'sleep',side_effect=wait), \
                patch.object(signal.socket,'MSG_DONTWAIT',64,create=True):
            code,receipt,_,isolate,_=prior._previous(fixture,prerequisite,actual)
        self.assertEqual(fixture.g.journal_sends,1,(receipt,order))
        self.assertEqual(fixture.g.authority_sends,0)
        self.assertEqual(fixture.g.refs[e.w.REF],e.w.BASELINE)
        self.assertEqual(fixture.g.row(fixture.g.refs[j.REF])['type'],'CONSUMED')
        self.assertEqual(client.deadline,100.0+budget,'Never reset helper deadline')
        client.close.assert_called_once()
        fixture.obj._call=api
        recovered=j.Journal(e.writer(fixture.g,51,e.pc.OUTAGE))
        self.assertIn(e.pc.OUTAGE,recovered.used)
        before=fixture.g.journal_sends
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(ValueError):
            recovered.consume(recovered.operation_binding(e.w._canonical(e.PLAN['infrastructure']),e.pc.OUTAGE))
        self.assertEqual(fixture.g.journal_sends,before,'No refund or retry')
        return code,receipt,isolate,order,reads

    def test_confirmation_old_child_before_actual_isolation(self):
        code,_,isolate,order,reads=self.run_case(['P','C'])
        self.assertEqual(code,0);isolate.assert_called_once()
        self.assertEqual(reads,['P','C','C','C'])
        self.assertEqual(order[0:2],[('prerequisite',0),('qualify',0)])
        self.assertEqual(order[-2:],[('qualify',1),('isolation',1)])

    def test_maximum_stabilization_still_requires_budget(self):
        code,_,isolate,_,reads=self.run_case(['P','P','C'],52)
        self.assertEqual(code,0);isolate.assert_called_once();self.assertEqual(len(reads),5)

    def test_insufficient_budget_after_exact_confirmation_is_consumed_failure(self):
        code,receipt,isolate,order,_=self.run_case(['P','P','C'],51)
        self.assertEqual(code,1);isolate.assert_not_called()
        self.assertEqual(receipt['result'],'D04_FAILED_CONSUMED')
        self.assertEqual(receipt['d04']['stage'],'POSTCONFIRMATION_READINESS')
        self.assertIsNotNone(receipt['d04']['consumed_record'])
        self.assertEqual(receipt['journal_confirmation']['result'],'CONFIRMED')
        self.assertEqual(order[-1],('qualify',1))

    def test_persistent_parent_is_unconfirmed_never_unspent(self):
        code,receipt,isolate,order,reads=self.run_case(['P','P','P'])
        self.assertEqual(code,1);isolate.assert_not_called()
        self.assertEqual(receipt['result'],'D04_CONSUMPTION_UNCONFIRMED')
        self.assertIsNone(receipt['d04']['consumed_record'])
        self.assertTrue(receipt['d04']['consumption_attempted'])
        self.assertEqual(receipt['journal_confirmation']['reason'],'PARENT_UNCONFIRMED')
        self.assertEqual(reads,['P','P','P']);self.assertNotIn(('qualify',1),order)

    def test_conflicting_head_is_consumed_block_no_isolation(self):
        code,receipt,isolate,order,reads=self.run_case(['S'])
        self.assertEqual(code,1);isolate.assert_not_called()
        self.assertEqual(receipt['journal_confirmation']['reason'],'CONFLICTING_HEAD')
        self.assertEqual(reads,['S']);self.assertNotIn(('qualify',1),order)


class Lifecycle(unittest.TestCase):
    def test_D03_deliberate_loss_precedes_helper_even_when_C_is_available(self):
        fixture=r3j_regression.original.V4();fixture.setUp()
        entered=[];original=j.Journal._confirm_append
        def observed(journal,parent,child,row,evidence):
            entered.append(row['type']);return original(journal,parent,child,row,evidence)
        with patch.object(j.Journal,'_confirm_append',observed),contextlib.redirect_stdout(io.StringIO()):
            obj,result=fixture.d03()
        self.assertEqual(entered,['CONSUMED','PENDING','SEND_ARMED'])
        self.assertEqual(fixture.g.calls[-1][0],'PATCH')
        self.assertEqual(result['result'],'INDETERMINATE')
        self.assertEqual(obj._journal_confirmation['reason'],'D03_CONFIRMATION_LOST')
        self.assertEqual(obj._journal_confirmation['observed_heads'],[])
        self.assertEqual(obj._journal_confirmation['result'],'BLOCKED')

    def test_pending_confirmation_never_grants_send_permission(self):
        rig=Rig('PENDING');rig.provider(['P','C'])
        with patch.object(j.time,'sleep'),contextlib.redirect_stdout(io.StringIO()):rig.invoke()
        self.assertIsNone(rig.journal._permit)
        with self.assertRaises(ValueError):rig.journal.take_send(rig.candidate)
        self.assertEqual(rig.g.authority_sends,0)

    def test_terminal_requires_original_affirmative_evidence_before_PATCH(self):
        rig=Rig('TERMINAL');pending=next(iter(rig.journal.pending))
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(ValueError):
            rig.journal.finish(pending,'e'*40,'UNARMED')
        self.assertEqual(rig.g.journal_sends-rig.before,0)

    def test_ordinary_outer_handler_retains_bounded_append_receipt(self):
        rig=Rig('SEND_ARMED');rig.provider(['P','P','P'])
        def main(context):
            context.update(writer=rig.obj,identity={})
            rig.invoke()
        with patch.object(ar,'main',side_effect=main),patch.object(ar,'current_binding',return_value={}), \
                patch.object(ar.dia,'blocked'),patch.object(j.time,'sleep'),contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ar.execute(),1)
        result=json.loads(next(line.removeprefix('PROOF6_RESULT ') for line in output.getvalue().splitlines() if line.startswith('PROOF6_RESULT ')))
        self.assertEqual(result['journal_confirmation']['reason'],'PARENT_UNCONFIRMED')
        self.assertFalse(result['update_attempted'])
        self.assertIsNone(rig.journal._permit)

    def test_invalid_diagnostic_identity_cannot_leak_or_admit(self):
        rig=Rig('CONSUMED');rig.obj._receipt_binding['runtime_sha']='INERT_SECRET_INVALID'
        with contextlib.redirect_stdout(io.StringIO()) as output,self.assertRaises(ValueError):rig.invoke()
        self.assertNotIn('INERT_SECRET',output.getvalue()+json.dumps(rig.obj._journal_confirmation))
        self.assertEqual(rig.g.journal_sends,0)
        self.assertEqual(rig.obj._journal_confirmation['result'],'BLOCKED')


if __name__=='__main__':
    with patch.object(socket,'socket',side_effect=AssertionError('OFFLINE_ONLY')):
        unittest.main(argv=[__file__],verbosity=2)
