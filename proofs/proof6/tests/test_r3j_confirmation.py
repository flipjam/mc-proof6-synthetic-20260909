"""Real ordinary append paths against an inert Git provider; never live writes."""
import contextlib
import copy
import io
import json
import unittest
from unittest.mock import patch
import urllib.error
import r3j_regression
from r3j_support import legacy as e
import journal as j
import writer as w
import journal_confirmation as diagnostic


class Rig:
    def __init__(self, kind):
        self.g = e.Git()
        self.obj = e.writer(self.g, 50, e.pc.OUTAGE if kind == 'CONSUMED' else '')
        self.journal = j.Journal(self.obj)
        proposal = w._canonical(e.PLAN['infrastructure'] if kind == 'CONSUMED' else e.PLAN['faults'][e.pc.FAULTS[0]]['proposal'])
        binding = self.journal.operation_binding(proposal, e.pc.OUTAGE if kind == 'CONSUMED' else '')
        self.candidate = self.g.commit(self.g.objects[w.BASELINE]['tree']['sha'], [w.BASELINE], 'inert-authority-candidate')
        if kind == 'CONSUMED':
            self.invoke = lambda: self.journal.consume(binding)
        elif kind == 'PENDING':
            self.invoke = lambda: self.journal.begin(binding,w.BASELINE,self.candidate,{'decision':'ALLOW'})
        else:
            with contextlib.redirect_stdout(io.StringIO()):
                pending = self.journal.begin(binding,w.BASELINE,self.candidate,{'decision':'ALLOW'})
            if kind == 'SEND_ARMED':
                self.invoke = lambda: self.journal.arm(pending)
            else:
                # Ordinary unarmed terminal has its own affirmative requirements.
                self.invoke = lambda: self.journal.finish(pending,w.BASELINE,'UNARMED')
        self.parent = self.journal.head
        self.before = self.g.journal_sends
        self.start_calls = len(self.g.calls)
        self.child = None
        self.ref_reads = 0
        self.commits_read = 0
        self.snapshots = []
        self.api = self.g.api

    def provider(self, sequence, response='success', mutation=None):
        def api(token,method,path,body=None):
            if method == 'PATCH':
                result = self.api(token,method,path,body)
                self.child = body['sha']
                self.record = copy.deepcopy(self.g.row(self.child))
                if mutation:
                    mutation(self)
                if response == 'exception':
                    raise OSError('INERT_SECRET_EXCEPTION_DO_NOT_LOG')
                if response == 'malformed':
                    return {'INERT_SECRET_RESPONSE_BODY':object()}
                return result
            if self.child and method == 'GET' and path == j.BASE+'/git/ref/'+j.REF.removeprefix('refs/'):
                self.ref_reads += 1
                self.g.calls.append((method,path,body))
                item = sequence[self.ref_reads-1] if self.ref_reads <= len(sequence) else 'C'
                self.snapshots.append(copy.deepcopy(self.journal._permit))
                if isinstance(item, BaseException):
                    raise item
                if item == 'malformed':
                    return {'ref':j.REF,'object':{'type':'commit','sha':None}}
                if item == 'missing':
                    return {}
                head = {'P':self.parent,'C':self.child,'S':'b'*40,'D':'c'*40}.get(item,item)
                return {'ref':j.REF,'object':{'type':'commit','sha':head}}
            if self.child and method == 'GET' and '/git/commits/' in path:
                self.commits_read += 1
            return self.api(token,method,path,body)
        self.obj._call = api

    def changed_row(self, change):
        row = copy.deepcopy(self.record)
        change(row)
        tree = self.g.tree(self.g.blob(w._canonical(row)))
        # Simulate an inconsistent protected read with independently valid blob
        # bytes. It must not qualify solely because the ref still reports C.
        self.g.objects[self.child]['tree']['sha'] = tree


CASES = {
 'immediate': (['C'], True, 0, 'EXACT_APPEND'),
 'old_child': (['P','C'], True, 1, 'EXACT_APPEND'),
 'old_old_child': (['P','P','C'], True, 2, 'EXACT_APPEND'),
 'persistent_parent': (['P','P','P'], False, 2, 'PARENT_UNCONFIRMED'),
 'child_then_parent': (['C','P'], False, 0, 'RECONSTRUCTION_ENTRY_MISMATCH'),
 'child_then_sibling': (['C','S'], False, 0, 'RECONSTRUCTION_ENTRY_MISMATCH'),
 'child_then_descendant': (['C','D'], False, 0, 'RECONSTRUCTION_ENTRY_MISMATCH'),
 'first_sibling': (['S'], False, 0, 'CONFLICTING_HEAD'),
 'first_descendant': (['D'], False, 0, 'CONFLICTING_HEAD'),
 'old_then_sibling': (['P','S'], False, 1, 'CONFLICTING_HEAD'),
 'malformed_ref': (['malformed'], False, 0, 'REF_OBSERVATION_FAILED'),
 'missing_ref': (['missing'], False, 0, 'REF_OBSERVATION_FAILED'),
 'read_transport_error': ([OSError('INERT_SECRET_READ_ERROR')], False, 0, 'REF_OBSERVATION_FAILED'),
 'conversion_error': ([ValueError('INERT_SECRET_CONVERSION')], False, 0, 'REF_OBSERVATION_FAILED'),
 'old_then_error': (['P',OSError('INERT_SECRET_READ_ERROR')], False, 1, 'REF_OBSERVATION_FAILED'),
 'old_then_malformed': (['P','malformed'], False, 1, 'REF_OBSERVATION_FAILED'),
 'reconstruction_final_parent': (['C','C','P'], False, 0, 'RECONSTRUCTION_FINAL_MISMATCH'),
 'reconstruction_final_sibling': (['C','C','S'], False, 0, 'RECONSTRUCTION_FINAL_MISMATCH'),
 'reconstruction_final_descendant': (['C','C','D'], False, 0, 'RECONSTRUCTION_FINAL_MISMATCH'),
 'reconstruction_entry_error': (['C',OSError('INERT_SECRET_RECONSTRUCTION')], False, 0, 'RECONSTRUCTION_FAILED'),
 'reconstruction_final_error': (['C','C',OSError('INERT_SECRET_RECONSTRUCTION')], False, 0, 'RECONSTRUCTION_FAILED'),
}


class Confirmation(unittest.TestCase):
    def exercise(self, kind, sequence, success, waits, reason, response='success', mutation=None):
        rig = Rig(kind)
        rig.provider(sequence,response,mutation)
        output = io.StringIO()
        with patch.object(j.time,'sleep') as sleep, contextlib.redirect_stdout(output), \
                patch.object(rig.journal,'read',wraps=rig.journal.read) as reconstruction:
            if success:
                rig.invoke()
            else:
                with self.assertRaises(Exception): rig.invoke()
        self.assertEqual(rig.g.journal_sends-rig.before,1)
        calls = rig.g.calls[rig.start_calls:]
        writes = [(method,path,body) for method,path,body in calls if method=='PATCH']
        self.assertEqual(len(writes),1)
        self.assertEqual(writes[0][2],{'sha':rig.child,'force':False})
        self.assertEqual(len([x for x in calls if x[0]=='POST']),3)
        self.assertFalse(any(x[0] in ('POST','PATCH') for x in calls[calls.index(writes[0])+1:]))
        self.assertEqual([x.args for x in sleep.call_args_list],[(1,)]*waits)
        receipt = rig.obj._journal_confirmation
        self.assertEqual(receipt['reason'],reason)
        self.assertEqual(receipt['result'],'CONFIRMED' if success else 'BLOCKED')
        self.assertEqual(receipt['parent'],rig.parent)
        self.assertEqual(receipt['candidate'],rig.child)
        self.assertEqual(receipt['record_sha256'],w._digest(w._canonical(rig.record)))
        self.assertTrue(receipt['patch_entered'])
        self.assertLessEqual(len(receipt['observed_heads']),3)
        expected=[]
        for value in sequence[:3]:
            if value in ('P','C','S','D'):
                expected.append({'P':rig.parent,'C':rig.child,'S':'b'*40,'D':'c'*40}[value])
            if value!='P':break
        self.assertEqual(receipt['observed_heads'],expected)
        for line in output.getvalue().splitlines():
            self.assertTrue(line.startswith('PROOF6_JOURNAL_APPEND '))
            event=json.loads(line.removeprefix('PROOF6_JOURNAL_APPEND '))
            self.assertEqual(event['schema'],diagnostic.SCHEMA)
            self.assertIn(event['stage'],diagnostic.STAGES)
            self.assertIn(event['reason'],diagnostic.REASONS)
        self.assertEqual(reconstruction.call_count,1 if 'C' in sequence[:3] else 0)
        self.assertTrue(all(x is None for x in rig.snapshots),'No send permit before confirmation')
        self.assertEqual(rig.g.authority_sends,0)
        self.assertEqual(rig.g.refs[w.REF],w.BASELINE)
        self.assertNotIn('INERT_SECRET',output.getvalue())
        if success:
            self.assertEqual(rig.journal.rows[-1],(rig.child,rig.record))
            self.assertEqual(rig.journal.head,rig.child)
            self.assertEqual(receipt['reconstruction_entry_head'],rig.child)
            self.assertEqual(receipt['reconstruction_final_head'],rig.child)
        if kind != 'SEND_ARMED' or not success:
            self.assertIsNone(rig.journal._permit)
            with self.assertRaises(ValueError):rig.journal.take_send(rig.candidate)
        else:
            rig.obj._call=rig.api
            rig.journal.take_send(rig.candidate)
            with self.assertRaises(ValueError):rig.journal.take_send(rig.candidate)
        return rig


def add(name, fn):
    setattr(Confirmation,'test_'+name,fn)

for kind in ('CONSUMED','PENDING','SEND_ARMED','TERMINAL'):
    for name,args in CASES.items():
        def test(self,kind=kind,args=args):self.exercise(kind,*args)
        add(kind+'_'+name,test)
    for name,sequence,success,waits,reason in (
        ('exception_child',['C'],True,0,'EXACT_APPEND'),
        ('lost_response_old_child',['P','C'],True,1,'EXACT_APPEND'),
        ('exception_persistent_parent',['P','P','P'],False,2,'PARENT_UNCONFIRMED')):
        def test(self,kind=kind,sequence=sequence,success=success,waits=waits,reason=reason):
            rig=self.exercise(kind,sequence,success,waits,reason,response='exception')
            self.assertEqual(rig.obj._journal_confirmation['patch_response'],'UNKNOWN')
            self.assertEqual(rig.obj._journal_confirmation['patch_call'],'EXCEPTION')
        add(kind+'_'+name,test)
    def malformed_response(self,kind=kind):
        self.exercise(kind,['C'],True,0,'EXACT_APPEND',response='malformed')
    add(kind+'_malformed_PATCH_body_does_not_replace_canonical_proof',malformed_response)
    for name,mutation,reason in (
        ('malformed_record',lambda r:r.changed_row(lambda row:row.update(unexpected=True)),'RECONSTRUCTION_FAILED'),
        ('wrong_schema',lambda r:r.changed_row(lambda row:row.update(schema='WRONG')),'RECONSTRUCTION_FAILED'),
        ('wrong_parent',lambda r:r.g.objects[r.child].update(parents=[{'sha':'e'*40}]),'RECONSTRUCTION_PARENT_MISMATCH'),
        ('ancestry_error',lambda r:r.g.objects[r.child].update(tree={'sha':'e'*40}),'RECONSTRUCTION_FAILED')):
        def test(self,kind=kind,mutation=mutation,reason=reason):self.exercise(kind,['C'],False,0,reason,mutation=mutation)
        add(kind+'_'+name,test)

for kind in ('CONSUMED','PENDING'):
    for field,value in (('run_id',99),('run_attempt',2),('caller',{}),('runtime_sha','e'*40),('manifest_sha256','e'*64),('plan_sha256','e'*64),('build_sha256','e'*64)):
        def test(self,kind=kind,field=field,value=value):
            self.exercise(kind,['C'],False,0,'RECORD_MISMATCH' if field=='run_id' else 'RECONSTRUCTION_FAILED',
                mutation=lambda r:r.changed_row(lambda row:row['binding'].update({field:value})))
        add(kind+'_wrong_'+field,test)


class Metadata(unittest.TestCase):
    def run_response(self, raw, status=200, request_id='OFFLINE:REQUEST', error=False):
        rig=Rig('CONSUMED');api=rig.api;responses=[]
        class Response:
            headers={'x-github-request-id':request_id}
            def __init__(self):self.status=status
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,bound):
                self_test.assertEqual(bound,2_000_001)
                return raw
        self_test=self
        def call(token,method,path,body=None):
            if method!='PATCH':return api(token,method,path,body)
            api(token,method,path,body);rig.child=body['sha']
            # Real _Writer._call receives a parsed/failed HTTP body AFTER the
            # inert provider has already applied the only possible mutation.
            return w._Writer._call(rig.obj,token,method,path,body)
        def open_response(request,timeout):
            responses.append(request)
            if error:
                failure=urllib.error.HTTPError('https://api.github.com',status,'INERT_SECRET_ERROR',{'x-github-request-id':request_id},None)
                failure.close()
                raise failure
            return Response()
        rig.obj._call=call
        with patch.object(rig.obj._http,'open',side_effect=open_response),contextlib.redirect_stdout(io.StringIO()) as output:
            rig.invoke()
        self.assertEqual(rig.g.journal_sends,1)
        self.assertEqual(len(responses),1)
        self.assertEqual(rig.obj._journal_confirmation['result'],'CONFIRMED')
        self.assertNotIn('INERT_SECRET',output.getvalue())
        return rig.obj._journal_confirmation

    def test_successful_http_metadata(self):
        value=self.run_response(b'{}')
        self.assertEqual((value['patch_response'],value['http_status'],value['request_id']),('PARSED_RESPONSE',200,'OFFLINE:REQUEST'))

    def test_parse_failure_preserves_http_metadata_before_confirmation(self):
        value=self.run_response(b'INERT_SECRET_RESPONSE_BODY')
        self.assertEqual((value['patch_call'],value['patch_response'],value['http_status']),('EXCEPTION','HTTP_RESPONSE',200))

    def test_http_exception_with_exact_reconstruction(self):
        value=self.run_response(b'',503,error=True)
        self.assertEqual((value['patch_call'],value['http_status']),('EXCEPTION',503))

    def test_bounded_metadata(self):
        for status,request_id in ((True,'INERT_SECRET\nHEADER'),('200','x'*129),(999,{}),(None,None)):
            value=self.run_response(b'{}',status,request_id)
            self.assertIsNone(value['http_status']);self.assertIsNone(value['request_id'])

    def test_metadata_does_not_observe_authority_or_other_calls(self):
        obj=Rig('CONSUMED').obj
        observer=__import__('unittest.mock',fromlist=['Mock']).Mock()
        obj._journal_append_observer=observer
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,*args):return b'{}'
        with patch.object(obj._http,'open',return_value=Response()):
            for method,path in (('GET',j.BASE+'/git/ref/heads/proof6-operation-journal-r3j'),('PATCH',j.BASE+'/git/refs/heads/proof6-authority')):
                w._Writer._call(obj,'offline-token',method,path,{})
        observer.assert_not_called()
        self.assertEqual(observer.method_calls,[])

    def test_diagnostic_failure_before_PATCH_blocks_mutation(self):
        rig=Rig('CONSUMED')
        with patch('builtins.print',side_effect=OSError('INERT_SECRET_PRINT')):
            with self.assertRaises(OSError):rig.invoke()
        self.assertEqual(rig.g.journal_sends,0)

    def test_diagnostic_failure_after_PATCH_never_releases_permit(self):
        rig=Rig('SEND_ARMED');rig.provider(['C'])
        def emit(*args,**kwargs):
            if '"result":"CONFIRMED"' in args[0]:raise OSError('INERT_SECRET_PRINT')
        with patch('builtins.print',side_effect=emit):
            with self.assertRaises(OSError):rig.invoke()
        self.assertEqual(rig.g.journal_sends-rig.before,1)
        self.assertIsNone(rig.journal._permit)
        self.assertEqual(rig.obj._journal_confirmation['result'],'BLOCKED')
        self.assertEqual(rig.obj._journal_confirmation['reason'],'DIAGNOSTIC_FAILURE')

    def test_backoff_error_not_retried(self):
        value=urllib.error.HTTPError('offline',429,'INERT_SECRET',{'Retry-After':'60'},None)
        try:Confirmation().exercise('CONSUMED',[value],False,0,'REF_OBSERVATION_FAILED')
        finally:value.close()


if __name__=='__main__':
    import socket
    with patch.object(socket,'socket',side_effect=AssertionError('OFFLINE_ONLY')):
        unittest.main(argv=[__file__],verbosity=2)
