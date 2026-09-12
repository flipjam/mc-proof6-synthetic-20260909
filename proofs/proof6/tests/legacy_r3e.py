"""Offline falsification only: in-memory Git/HTTPS, no network or live isolation."""
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
import urllib.error

ROOT = Path(sys.argv.pop(1)).resolve()
sys.path.insert(0, str(ROOT / 'proofs/proof6'))
import writer as w
import journal as j
import proof_control as pc
import actions_runtime as ar
import outage
import d03_rejection as dr
import d03_job_token as jt

PLAN, PD = pc.plan()
HISTORY = json.loads(subprocess.check_output(['git', '-C', str(ROOT), 'show', w.BASELINE + ':history.json']))
CALLER = dict(login='peaklinesoftware', id=265169095, permission='write', admin=False, maintain=False,
              environment_qualification='required separately in case evidence; not attested by account permission')


def real_response(raw):
    class Socket:
        def makefile(self, mode):
            assert mode=='rb'
            return io.BytesIO(raw)
    response=w.http.client.HTTPResponse(Socket())
    response.begin()
    return response


class Crash(BaseException):
    pass


class Git:
    def __init__(self):
        self.objects = {}; self.refs = {}; self.calls = []; self.journal_sends = 0
        self.authority_sends = 0; self.revoked = False; self.status = 200
        self.delay = False; self.received = False; self.ambiguity = None; self.crash = None
        self.expected_token = "offline-token"; self.error_body = None; self.headers = {}
        self.response_wire = None; self.last_response = None
        self.rules = {}
        for ident, kind, types in [(901, 'integrity', ['creation','deletion','non_fast_forward']), (902, 'update', ['update'])]:
            self.rules[kind] = dict(id=ident, name='offline-'+kind, target='branch', source_type='Repository', source=w.REPO,
                enforcement='active', conditions={'ref_name': {'include':[j.REF], 'exclude':[]}},
                rules=[{'type':t} for t in types], updated_at='2026-09-10T00:00:00.000+00:00')
        self.genesis, self.genesis_tree = self.record(j.GENESIS, None)
        self.refs[j.REF] = self.genesis
        tree = self.tree(self.blob(w._canonical(HISTORY)), 'history.json')
        self.objects[w.BASELINE] = dict(sha=w.BASELINE, tree={'sha':tree}, parents=[])
        self.refs[w.REF] = w.BASELINE

    def blob(self, raw):
        sha = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        self.objects[sha] = dict(sha=sha, encoding='base64', content=base64.b64encode(raw).decode())
        return sha

    def tree(self, blob, path=j.PATH):
        entries=[dict(path=path, mode='100644', type='blob', sha=blob)]
        sha=hashlib.sha1(w._canonical(entries)).hexdigest()
        self.objects[sha]=dict(sha=sha, truncated=False, tree=entries)
        return sha

    def commit(self, tree, parents, message):
        sha=hashlib.sha1(w._canonical([tree,parents,message])).hexdigest()
        self.objects[sha]=dict(sha=sha, tree={'sha':tree}, parents=[{'sha':p} for p in parents])
        return sha

    def record(self, row, parent):
        tree=self.tree(self.blob(w._canonical(row)))
        return self.commit(tree, [] if parent is None else [parent], 'fixture'),tree

    def row(self, sha):
        tree=self.objects[self.objects[sha]['tree']['sha']]
        return json.loads(base64.b64decode(self.objects[tree['tree'][0]['sha']]['content']))

    def advance(self, ref, child):
        old=self.refs[ref]; cursor=child; seen=set()
        while cursor != old:
            if cursor in seen or len(self.objects[cursor]['parents']) != 1:
                raise urllib.error.HTTPError('offline',409,'conflict',{},None)
            seen.add(cursor);cursor=self.objects[cursor]['parents'][0]['sha']
        self.refs[ref]=child

    def api(self, token, method, path, body=None):
        assert token == "offline-token"  # Every ordinary read/object/journal call uses the App.
        self.calls.append((method,path,body))
        if self.revoked:
            raise urllib.error.HTTPError('offline',401,'revoked',{},None)
        assert path.startswith(j.BASE)
        suffix=path[len(j.BASE):]
        if method=='GET':
            if suffix.startswith('/rulesets/'):
                return copy.deepcopy(next(v for v in self.rules.values() if v['id']==int(suffix.split('/')[-1])))
            if suffix.startswith('/git/ref/'):
                ref='refs/'+suffix[len('/git/ref/'):]
                return dict(ref=ref,object=dict(type='commit',sha=self.refs[ref]))
            if suffix.startswith('/compare/'):return dict(status='ahead')
            return copy.deepcopy(self.objects[suffix.split('/')[-1]])
        if method=='POST':
            if suffix=='/git/blobs':return {'sha':self.blob(base64.b64decode(body['content']))}
            if suffix=='/git/trees':
                assert len(body['tree'])==1
                return {'sha':self.tree(body['tree'][0]['sha'],body['tree'][0]['path'])}
            if suffix=='/git/commits':return {'sha':self.commit(body['tree'],body['parents'],body['message'])}
        assert method=='PATCH' and suffix=='/git/refs/heads/proof6-operation-journal-r3e'
        assert body['force'] is False
        self.journal_sends+=1
        kind=self.row(body['sha'])['type']
        if self.crash==('before',kind):raise Crash()
        if self.ambiguity=='old':raise OSError('lost before delivery')
        if self.ambiguity=='sibling':
            sibling,_=self.record(dict(j.GENESIS, extra=True),self.refs[j.REF])
            self.refs[j.REF]=sibling
        self.advance(j.REF,body['sha'])
        if self.crash==('after',kind):raise Crash()
        if self.ambiguity=='child':raise OSError('response lost')
        return {'ref':j.REF,'object':{'sha':body['sha']}}

    def connection(self, host, timeout):
        assert host=='api.github.com' and timeout==30
        git=self
        class Connection:
            def request(self,method,path,body,headers):
                assert method=='PATCH' and path==j.BASE+'/git/refs/heads/proof6-authority'
                data=json.loads(body);assert data['force'] is False
                assert headers['Authorization']=='Bearer '+git.expected_token
                assert git.row(git.refs[j.REF])['type']=='SEND_ARMED'
                if git.expected_token=='offline-job-token':assert headers['Connection']=='close'
                else:assert 'Connection' not in headers
                git.authority_sends+=1
                if git.crash==('before','AUTHORITY'):raise Crash()
                if not git.delay and git.status==200:git.advance(w.REF,data['sha'])
                self.candidate=data['sha']
                if git.crash==('after','AUTHORITY'):raise Crash()
            def getresponse(self):
                git.received=True
                data=git.error_body if git.error_body is not None else w._canonical({'ref':w.REF,'object':{'sha':self.candidate}})
                headers=dict({'Content-Length':str(len(data)),'x-github-request-id':'OFFLINE:REQUEST'},**git.headers)
                raw=('HTTP/1.1 '+str(git.status)+' Response\r\n').encode()+b''.join(
                    (k+': '+v+'\r\n').encode() for k,v in headers.items() if v is not None)+b'\r\n'+data
                git.last_response=real_response(git.response_wire if git.response_wire is not None else raw)
                return git.last_response
            def close(self):pass
        return Connection()


def manifest(g):
    return dict(contract_commit='34b940e0537f57e5fa225768a55214bd3d3c5340',revision=3,frozen=True,
        runtime_variant='r3e',repository_id=w.REPO_ID,repository=w.REPO,ref=w.REF,baseline_commit=w.BASELINE,
        app_id=w.APP_ID,installation_id=w.INSTALLATION,app_slug='mc-proof-6-gate-writer',token_permissions=w.PERMISSIONS,
        action={'repository':w.ACTION_REPOSITORY,'commit':w.ACTION_COMMIT},configuration_sha256=w.CONFIG_DIGEST,
        authority_visible_sha256=w.VISIBLE_CONFIG_DIGEST,accepted_code_sha256=w.CODE,
        writer_sha256=w._digest((ROOT/'proofs/proof6/writer.py').read_bytes()),proof_plan_sha256=PD,
        build_sha256=w._digest((ROOT/'proofs/proof6/build.json').read_bytes()),runtime={'sha':'a'*40},
        journal=dict(ref=j.REF,path=j.PATH,genesis_commit=g.genesis,genesis_tree=g.genesis_tree,
            genesis_content_sha256=w._digest(w._canonical(j.GENESIS)),schema_sha256=j.SCHEMA_SHA256,rulesets=g.rules))


def writer(g, n=50, op=''):
    obj=w._Writer(frozen_manifest=manifest(g),installation_token='offline-token',action_installation_id=str(w.INSTALLATION),
        action_app_slug='mc-proof-6-gate-writer',runtime_guard=lambda _:None,
        receipt_binding=dict(run_id=n,run_attempt=1,runtime_sha='a'*40,caller=CALLER,proof_operation=op,proof_plan_sha256=PD))
    obj._call=g.api;obj._installation_access=lambda:'offline-token';obj._enforcement=lambda _:None
    return obj


class Candidate(unittest.TestCase):
    def setUp(self):
        self.g=Git();self.w=writer(self.g);self.j=j.Journal(self.w)
        self.proposal=w._canonical(PLAN['faults'][pc.FAULTS[0]]['proposal'])

    def begin(self, op='', n=50):
        obj=writer(self.g,n,op);journal=j.Journal(obj)
        payload=w._canonical(PLAN['faults'][op]['proposal']) if op else self.proposal
        b=journal.operation_binding(payload,op)
        if op:journal.consume(b)
        candidate=self.g.commit(self.g.objects[w.BASELINE]['tree']['sha'],[w.BASELINE],str(n))
        return journal,journal.begin(b,w.BASELINE,candidate,{'decision':'ALLOW'}),candidate

    def run_writer(self, op='', n=50, proposal=None):
        obj=writer(self.g,n,op)
        payload=proposal or w._canonical(PLAN['faults'][op or pc.FAULTS[0]]['proposal'])
        output=io.StringIO()
        with patch.object(w.http.client,'HTTPSConnection',self.g.connection),contextlib.redirect_stdout(output):
            result=obj.commit_transition(payload,op)
        self.output=output.getvalue()
        return obj,result

    def test_deleted_actions_cannot_refund_consumed(self):
        b=self.j.operation_binding(self.proposal,pc.FAULTS[0]);self.j.consume(b)
        for n in (51,1,999):
            fresh=j.Journal(writer(self.g,n,pc.FAULTS[0]))
            with self.assertRaises(ValueError):fresh.consume(fresh.operation_binding(self.proposal,pc.FAULTS[0]))

    def test_no_actions_history_required(self):
        journal,pending,_=self.begin();journal.arm(pending)
        for n in (99,1):
            fresh=j.Journal(writer(self.g,n))
            with self.assertRaises(ValueError):fresh.recover(lambda:w.BASELINE)
            self.assertIn(pending,fresh.pending)
        self.assertFalse(any('/actions/' in path for _,path,_ in self.g.calls))

    def test_lookalike_ignored(self):
        self.g.refs[j.REF+'-lookalike']=self.g.genesis
        del self.g.refs[j.REF]
        with self.assertRaises(KeyError):j.Journal(self.w)

    def test_ref_path_schema_and_genesis_binding(self):
        for key,value in [('ref',j.REF+'x'),('path','other.json'),('schema_sha256','0'*64),('genesis_tree','0'*40)]:
            obj=writer(self.g);obj._manifest=copy.deepcopy(obj._manifest);obj._manifest['journal'][key]=value
            with self.subTest(key=key),self.assertRaises((ValueError,KeyError)):j.Journal(obj)

    def test_malformed_unknown_duplicate_schema(self):
        for row in [dict(j.GENESIS,extra=True),{'type':'REPAIR','schema':j.SCHEMA}]:
            sha,_=self.g.record(row,self.g.genesis);self.g.refs[j.REF]=sha
            with self.assertRaises(ValueError):self.j.read()
        with self.assertRaises(ValueError):j.parse(b'{"a":1,"a":1}')

    def test_missing_ancestry_and_merge_block(self):
        journal,p,_=self.begin();head=self.g.refs[j.REF]
        self.g.objects[head]['parents']=[{'sha':'0'*40}]
        with self.assertRaises(KeyError):journal.read()
        self.g.objects[head]['parents']=[{'sha':self.g.genesis},{'sha':self.g.genesis}]
        with self.assertRaises(ValueError):journal.read()

    def test_extra_file_blocks(self):
        tree=self.g.objects[self.g.genesis_tree];tree['tree'].append(dict(tree['tree'][0],path='unrelated'))
        with self.assertRaises(ValueError):self.j.read()

    def test_sibling_conflict_blocks(self):
        self.g.ambiguity='sibling'
        with self.assertRaises(ValueError):self.j.consume(self.j.operation_binding(self.proposal,pc.FAULTS[0]))
        self.assertEqual(self.g.journal_sends,1)

    def test_ambiguous_append_child_confirmed_no_retry(self):
        self.g.ambiguity='child'
        self.j.consume(self.j.operation_binding(self.proposal,pc.FAULTS[0]))
        self.assertEqual(self.g.journal_sends,1);self.assertIn(pc.FAULTS[0],self.j.used)

    def test_ambiguous_append_old_blocks_no_retry(self):
        self.g.ambiguity='old'
        with self.assertRaises(ValueError):self.j.consume(self.j.operation_binding(self.proposal,pc.FAULTS[0]))
        self.assertEqual(self.g.journal_sends,1)

    def test_stale_head_blocks_before_append(self):
        stale=j.Journal(self.w)
        self.j.consume(self.j.operation_binding(self.proposal,pc.FAULTS[0]))
        before=self.g.journal_sends
        with self.assertRaises(ValueError):stale.consume(stale.operation_binding(w._canonical(PLAN['faults'][pc.FAULTS[1]]['proposal']),pc.FAULTS[1]))
        self.assertEqual(self.g.journal_sends,before)

    def test_pending_required_for_arm(self):
        with self.assertRaises(ValueError):self.j.arm('1'*40)

    def test_arm_required_for_transport(self):
        journal,p,c=self.begin()
        with self.assertRaises(ValueError):journal.take_send(c)
        with self.assertRaises(ValueError):self.w._patch(c,False,{})
        self.assertEqual(self.g.authority_sends,0)
        with self.assertRaises(ValueError):self.w._patch(None,False,{})

    def test_fresh_invocation_cannot_arm_prior_operation(self):
        journal,p,c=self.begin()
        with self.assertRaises(ValueError):j.Journal(writer(self.g,51)).arm(p)

    def test_transport_permit_is_single_use(self):
        journal,p,c=self.begin();journal.arm(p);journal.take_send(c)
        with self.assertRaises(ValueError):journal.take_send(c)
        obj=writer(self.g);obj._transport_candidate=c
        with patch.object(w.http.client,'HTTPSConnection',self.g.connection):
            obj._patch(c,False,{})
            with self.assertRaises(ValueError):obj._patch(c,False,{})
        self.assertEqual(self.g.authority_sends,1)

    def test_pending_crash_unarmed_resolution(self):
        journal,p,c=self.begin();fresh=j.Journal(writer(self.g,51))
        fresh.recover(lambda:w.BASELINE)
        self.assertIn(p,fresh.resolved);self.assertEqual(self.g.row(fresh.head)['evidence'],'UNARMED')
        with self.assertRaises(ValueError):journal.arm(p)
        self.assertEqual(self.g.authority_sends,0)

    def test_delayed_arming_loses_to_resolution(self):
        journal,p,c=self.begin();late,_=self.g.record(dict(schema=j.SCHEMA,type='SEND_ARMED',pending=p),journal.head)
        j.Journal(writer(self.g,51)).recover(lambda:w.BASELINE)
        with self.assertRaises(urllib.error.HTTPError):self.g.advance(j.REF,late)

    def test_armed_old_never_released(self):
        journal,p,c=self.begin();journal.arm(p)
        for _ in range(3):
            fresh=j.Journal(writer(self.g,1))
            with self.assertRaises(ValueError):fresh.recover(lambda:w.BASELINE)
            self.assertNotIn(p,fresh.resolved)

    def test_candidate_resolves_without_resend(self):
        journal,p,c=self.begin();journal.arm(p);self.g.refs[w.REF]=c
        fresh=j.Journal(writer(self.g,51));fresh.recover(lambda:c)
        self.assertIn(p,fresh.resolved);self.assertEqual(self.g.authority_sends,0)

    def test_other_unreadable_contradictory_blocks(self):
        journal,p,c=self.begin();journal.arm(p)
        with self.assertRaises(ValueError):journal.recover(lambda:'e'*40)
        with self.assertRaises(OSError):journal.recover(lambda:(_ for _ in ()).throw(OSError()))
        with self.assertRaises(ValueError):journal.finish(p,w.BASELINE,'UNARMED')

    def test_candidate_preexistence_not_authority(self):
        journal,p,c=self.begin();journal.arm(p)
        self.assertIn(c,self.g.objects)
        with self.assertRaises(ValueError):journal.recover(lambda:w.BASELINE)

    def test_reused_candidate_blocked(self):
        journal,p,c=self.begin();journal.recover(lambda:w.BASELINE)
        fresh=j.Journal(writer(self.g,51))
        with self.assertRaises(ValueError):fresh.begin(fresh.operation_binding(self.proposal,''),w.BASELINE,c,{'decision':'ALLOW'})

    def test_terminal_ambiguity_does_not_release(self):
        journal,p,c=self.begin();self.g.ambiguity='old'
        with self.assertRaises(ValueError):journal.finish(p,w.BASELINE,'UNARMED')
        fresh=j.Journal(writer(self.g,51));self.assertNotIn(p,fresh.resolved)

    def test_normal_real_gate_single_patch_and_stale(self):
        obj,result=self.run_writer();self.assertEqual(result['result'],'COMMITTED')
        kinds=[self.g.row(sha)['type'] for sha,_ in obj._journal.rows]
        self.assertEqual(kinds,['PENDING','SEND_ARMED','TERMINAL'])
        self.assertEqual(self.g.authority_sends,1)
        obj,result=self.run_writer(n=51);self.assertEqual(result['result'],'REJECTED')
        self.assertEqual(self.g.authority_sends,1)

    def test_d02_no_arm_no_patch_permanent(self):
        obj,result=self.run_writer(pc.FAULTS[0]);self.assertFalse(result['update_attempted'])
        self.assertIn('terminal_record',result);self.assertEqual(self.g.authority_sends,0)
        self.assertFalse(obj._journal.armed)
        obj,result=self.run_writer(pc.FAULTS[0],51);self.assertNotIn('gate',result)

    def test_genuine_final_rejection_durable(self):
        self.g.status=409
        obj,result=self.run_writer();self.assertEqual(result['remote_outcome'],'explicit_rejection')
        row=self.g.row(obj._journal.head)
        self.assertEqual(row['evidence'],'FINAL_REJECTION');self.assertEqual(row['status'],409)
        fresh=j.Journal(writer(self.g,51));fresh.recover(lambda:w.BASELINE)

    def test_d07_unknown_no_response_read_no_resend(self):
        obj,result=self.run_writer(pc.FAULTS[2]);self.assertEqual(result['result'],'INDETERMINATE')
        self.assertFalse(self.g.received);self.assertEqual(self.g.authority_sends,1)
        fresh=j.Journal(writer(self.g,51));fresh.recover(lambda:self.g.refs[w.REF])
        obj,result=self.run_writer(pc.FAULTS[2],52);self.assertNotIn('gate',result)
        self.assertEqual(self.g.authority_sends,1)

    def test_delayed_patch_blocks_before_gate(self):
        self.g.delay=True
        obj,result=self.run_writer(pc.FAULTS[2]);self.assertEqual(result['result'],'INDETERMINATE')
        obj=writer(self.g,51);obj._gate=Mock()
        with contextlib.redirect_stdout(io.StringIO()):out=obj.commit_transition(self.proposal)
        obj._gate.decide.assert_not_called();self.assertEqual(self.g.authority_sends,1)

    def test_consumption_binding_strict(self):
        b=self.j.operation_binding(self.proposal,pc.FAULTS[0])
        for k,v in [('caller',dict(CALLER,admin=True)),('run_attempt',2),('proposal_sha256','0'*64),('runtime_sha','0'*40),('operation','UNKNOWN')]:
            with self.subTest(key=k),self.assertRaises(ValueError):self.j.consume(dict(b,**{k:v}))

    def test_normal_no_fault_controls(self):
        for key in ('fault','journal','ref','file','parent','payload','token','command','duration','endpoint'):
            p=dict(json.loads(self.proposal),**{key:'x'})
            obj,result=self.run_writer(proposal=w._canonical(p))
            self.assertNotIn('gate',result);self.assertEqual(self.g.authority_sends,0)

    def test_proof_no_arbitrary_data(self):
        for data in [{'proof_operation':'UNKNOWN'},{'proof_operation':pc.FAULTS[0],'proposal':'{}'}, {'journal':{}}, {'proof_operation':pc.OUTAGE,'duration':1}]:
            with self.assertRaises(ValueError):pc.request(data)

    def test_manifest_tamper_rejected(self):
        for k,v in [('runtime_variant','r3c'),('contract_commit','0'*40),('ref','refs/heads/other'),('proof_plan_sha256','0'*64)]:
            with self.subTest(key=k),self.assertRaises(ValueError):self.w._check_manifest(dict(self.w._manifest,**{k:v}))

    def test_crash_boundaries(self):
        for kind in ('CONSUMED','PENDING','SEND_ARMED','AUTHORITY','TERMINAL'):
            for when in ('before','after'):
                with self.subTest(kind=kind,when=when):
                    self.g=Git();self.g.crash=(when,kind)
                    with self.assertRaises(Crash):self.run_writer(pc.FAULTS[2] if kind=='CONSUMED' else '')
                    self.g.crash=None
                    fresh=j.Journal(writer(self.g,51))
                    armed=bool(fresh.armed)
                    if armed and self.g.refs[w.REF]==w.BASELINE:
                        with self.assertRaises(ValueError):fresh.recover(lambda:self.g.refs[w.REF])
                    else:fresh.recover(lambda:self.g.refs[w.REF])
                    self.assertLessEqual(self.g.authority_sends,1)
                    if kind=='CONSUMED' and when=='after':self.assertIn(pc.FAULTS[2],fresh.used)

    def test_no_actions_membership_or_general_platform(self):
        for file in ('actions_runtime.py','journal.py','admission.py','outage.py'):
            text=(ROOT/'proofs/proof6'/file).read_text()
            for forbidden in ('/actions/workflows/','gh\', \'run','sqlite','redis','kafka','Popen','setns('):
                self.assertNotIn(forbidden,text)

    def test_d04_same_runtime_process_structure(self):
        text=(ROOT/'proofs/proof6/actions_runtime.py').read_text()
        self.assertLess(text.index('claim = journal.consume'),text.index('result = isolate_runtime'))
        self.assertLess(text.index('writer = _Writer'),text.index('result = isolate_runtime'))
        self.assertIn("writer._installation_token = ''",text)
        source=(ROOT/'proofs/proof6/outage.py').read_text()
        self.assertIn('libc.unshare(CLONE_NEWNET)',source);self.assertNotIn('subprocess',source)
        self.assertNotIn('_patch(',source);self.assertEqual(outage.MAX_SECONDS,120)
        workflow=(ROOT/'.github/workflows/proof6-writer.yml').read_text()
        self.assertIn('sudo -n --preserve-env=',workflow)
        self.assertIn('/usr/bin/python3 -B proofs/proof6/actions_runtime.py',workflow)
        self.assertIn('group: proof6-authority-writer-r3',workflow)
        self.assertIn('cancel-in-progress: false',workflow)

    def test_helper_only_isolation_fails(self):
        with patch.object(outage.socket,'if_nameindex',return_value=[(1,'lo'),(2,'eth0')]),self.assertRaises(ValueError):outage.isolated()

    def test_d04_unshare_and_observations_same_pid(self):
        libc=Mock();libc.unshare.return_value=0;events=[]
        with patch.object(outage.ctypes,'CDLL',return_value=libc), \
             patch.object(outage,'isolated',return_value={'api_github_connection':'unavailable'}), \
             patch.object(outage.time,'monotonic',side_effect=[0,115,116]):
            result=outage.isolate_runtime(events.append)
        self.assertEqual(result['result'],'OUTAGE_COMPLETED')
        libc.unshare.assert_called_once_with(outage.CLONE_NEWNET)
        self.assertEqual([e['phase'] for e in events],['START','READY','END'])
        self.assertEqual({e['pid'] for e in events},{os.getpid()})

    def test_d04_unshare_failure_blocks(self):
        libc=Mock();libc.unshare.return_value=-1;events=[]
        with patch.object(outage.ctypes,'CDLL',return_value=libc), \
             self.assertRaises(ValueError):outage.isolate_runtime(events.append)
        self.assertEqual([e['phase'] for e in events],['START'])

    def test_d04_main_consumes_then_isolates_actual_runtime(self):
        obj=writer(self.g,50,pc.OUTAGE);ctx={'writer':None};observed=[]
        env=dict(PROOF6_FROZEN_MANIFEST=json.dumps(obj._manifest),GITHUB_EVENT_PATH='unused-offline',
                 GITHUB_RUN_ID='50',GITHUB_RUN_ATTEMPT='1',GITHUB_SHA='a'*40,
                 PROOF6_APP_TOKEN='offline-token',PROOF6_APP_INSTALLATION_ID=str(w.INSTALLATION),
                 PROOF6_APP_SLUG='mc-proof-6-gate-writer')
        def isolate(emit):
            self.assertIs(ctx['writer'],obj)
            self.assertEqual(obj._installation_token,'')
            self.assertEqual(self.g.row(self.g.refs[j.REF])['type'],'CONSUMED')
            self.assertEqual(self.g.row(self.g.refs[j.REF])['binding']['operation'],pc.OUTAGE)
            self.assertEqual(self.g.authority_sends,0)
            observed.append(os.getpid())
            return dict(result='OUTAGE_COMPLETED',update_attempted=False,remote_outcome='not_attempted')
        event=json.dumps({'inputs':{'proof_operation':pc.OUTAGE}})
        with patch.dict(os.environ,env),patch.object(ar,'guard'),patch.object(pc,'qualify',return_value=CALLER), \
             patch.object(ar,'_Writer',return_value=obj),patch.object(outage,'isolate_runtime',isolate), \
             patch.object(Path,'read_text',return_value=event),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ar.main(ctx),0)
        self.assertEqual(observed,[os.getpid()])

    def test_workflow_dispatch_only(self):
        files=list((ROOT/'.github/workflows').glob('*'))
        self.assertEqual(len(files),1)
        text=files[0].read_text();self.assertIn('on:\n  workflow_dispatch:',text)
        for trigger in ('push:','pull_request:','create:','workflow_run:','schedule:'):self.assertNotIn(trigger,text)
        self.assertIn("github.ref == 'refs/heads/proof6-writer-runtime-r3e'",text)

    def test_source_build_and_accepted_gate(self):
        build=json.loads((ROOT/'proofs/proof6/build.json').read_bytes())
        self.assertIn('proofs/proof6/journal.py',build)
        for path,digest in build.items():
            raw=(ROOT/path).read_bytes();self.assertEqual(w._digest(raw),digest,path)
            if path.endswith('.py'):compile(raw,path,'exec')
        for path,digest in w.CODE.items():self.assertEqual(build[path],digest)


class Corrections(Candidate):
    def workflow_script(self):
        text=(ROOT/'.github/workflows/proof6-writer.yml').read_text()
        return '\n'.join(line[10:] for line in text.split('        run: |\n')[-1].split('      - name:')[0].splitlines())+'\n'

    def test_native_fixed_deadline_no_python_callback(self):
        script=self.workflow_script()
        self.assertIn('deadline=(/usr/bin/timeout --signal=KILL 120s)',script)
        self.assertIn('"${deadline[@]}" /usr/bin/python3 -B proofs/proof6/actions_runtime.py',script)
        source=(ROOT/'proofs/proof6/outage.py').read_text()
        for forbidden in ('SIGALRM','setitimer','signal.signal','setsid','setpgid','fork','subprocess'):
            self.assertNotIn(forbidden,source.replace('No forked probe/worker','No helper'))
        for data in ({'proof_operation':pc.OUTAGE,'duration':1},{'proof_operation':pc.OUTAGE,'timeout':0}):
            with self.assertRaises(ValueError):pc.request(data)

    def test_native_timeout_exit_cannot_credit_completion(self):
        script='sudo() { return 137; }\nexport PROOF6_OPERATION=D04_CONNECTIVITY_OUTAGE\n'+self.workflow_script()
        out=subprocess.run(['wsl','-d','Ubuntu-22.04','--','bash','-s'],input=script.encode(),capture_output=True,timeout=30)
        self.assertEqual(out.returncode,137,out.stderr)
        self.assertNotIn(b'PROOF6_D04_NATIVE_DEADLINE_COMPLETED',out.stdout)

    def test_native_normal_completion_marker_requires_child_success(self):
        script='sudo() { return 0; }\nexport PROOF6_OPERATION=D04_CONNECTIVITY_OUTAGE\n'+self.workflow_script()
        out=subprocess.run(['wsl','-d','Ubuntu-22.04','--','bash','-s'],input=script.encode(),capture_output=True,timeout=30)
        self.assertEqual(out.returncode,0,out.stderr)
        self.assertEqual(out.stdout.strip(),b'PROOF6_D04_NATIVE_DEADLINE_COMPLETED')

    def test_native_process_group_kill_leaves_no_running_child(self):
        # Harmless offline Linux process test: no writer, token, network or unshare.
        # Short test duration exercises the same native SIGKILL group behavior;
        # separate source assertion above pins the production duration to 120s.
        script="""import os, subprocess, time
code = 'import os,signal,subprocess,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); child=subprocess.Popen(["sleep","30"]); print(os.getpid(),child.pid,flush=True); time.sleep(30)'
p=subprocess.run(['/usr/bin/timeout','--signal=KILL','0.2s','python3','-c',code],capture_output=True,text=True,timeout=5)
assert p.returncode in (-9,137),p.returncode
pids=[int(x) for x in p.stdout.split()]; assert len(pids)==2,p.stdout
for pid in pids:
    path='/proc/'+str(pid)+'/stat'
    if os.path.exists(path): assert open(path).read().split()[2]=='Z',pid
print('OFFLINE_NATIVE_GROUP_KILL_OK')
"""
        out=subprocess.run(['wsl','-d','Ubuntu-22.04','--','python3','-'],input=script,text=True,capture_output=True,timeout=30)
        self.assertEqual(out.returncode,0,out.stderr);self.assertIn('OFFLINE_NATIVE_GROUP_KILL_OK',out.stdout)

    def test_d04_isolation_evidence_still_required(self):
        libc=Mock();libc.unshare.return_value=0;events=[]
        with patch.object(outage.ctypes,'CDLL',return_value=libc),patch.object(outage,'isolated',side_effect=ValueError()),self.assertRaises(ValueError):
            outage.isolate_runtime(events.append)
        self.assertNotIn('END',[e['phase'] for e in events])


class Bootstrap(unittest.TestCase):
    def context(self):
        return dict(GITHUB_REPOSITORY=w.REPO,GITHUB_REPOSITORY_ID=str(w.REPO_ID),
                    GITHUB_REF=ar.RUNTIME_REF,GITHUB_WORKFLOW_REF=w.REPO+'/'+ar.WORKFLOW+'@'+ar.RUNTIME_REF,
                    GITHUB_SHA='a'*40,GITHUB_RUN_ID='50',GITHUB_RUN_ATTEMPT='1',
                    RUNNER_ENVIRONMENT='github-hosted',GITHUB_EVENT_NAME='workflow_dispatch',
                    GITHUB_EVENT_PATH='offline-event',GITHUB_ACTOR='flipjam',GITHUB_ACTOR_ID='1',
                    GITHUB_TRIGGERING_ACTOR='flipjam',PROOF6_APP_TOKEN='offline-token',
                    PROOF6_APP_INSTALLATION_ID=str(w.INSTALLATION),PROOF6_APP_SLUG='mc-proof-6-gate-writer')

    def metadata(self,path):
        base='repos/'+w.REPO
        fixed={base+'/git/ref/heads/proof6-writer-runtime-r3e':dict(ref=ar.RUNTIME_REF,object=dict(type='commit',sha='a'*40)),
               base+'/environments/proof6-writer':dict(id=21620162130,name='proof6-writer',can_admins_bypass=False,
                    deployment_branch_policy=dict(protected_branches=False,custom_branch_policies=True)),
               base+'/environments/proof6-writer/deployment-branch-policies':dict(total_count=1,
                    branch_policies=[dict(id=900,name='proof6-writer-runtime-r3e',type='branch')])}
        self.assertIn(path,fixed)
        return fixed[path]

    def route(self,inputs=None,manifest=None,env_change=None,get=None):
        env=self.context();env.update(env_change or {})
        if manifest is not None:env['PROOF6_FROZEN_MANIFEST']=manifest
        event=json.dumps({'inputs':{} if inputs is None else inputs})
        ctx={'writer':None};output=io.StringIO()
        with patch.dict(os.environ,env,clear=True),patch.object(Path,'read_text',return_value=event), \
             patch.object(ar,'get',side_effect=get or self.metadata), \
             patch.object(ar,'setup_bootstrap_diagnostics',return_value=dict(result='APP_AUTH_SETUP_VERIFIED')) as diagnostic, \
             patch.object(ar,'_Writer',side_effect=AssertionError('WRITER_FORBIDDEN')) as writer_ctor, \
             patch.object(j,'Journal',side_effect=AssertionError('JOURNAL_FORBIDDEN')) as journal_ctor, \
             patch.object(w._Writer,'_patch',side_effect=AssertionError('PATCH_FORBIDDEN')) as transport, \
             patch.object(jt,'bind',side_effect=AssertionError('D03_FORBIDDEN')) as revoke, \
             patch.object(outage,'isolate_runtime',side_effect=AssertionError('D04_FORBIDDEN')) as isolate, \
             contextlib.redirect_stdout(output):
            try:
                code=ar.main(ctx);result=json.loads(output.getvalue().split('PROOF6_RESULT ',1)[1])
            except (ValueError,KeyError,TypeError):
                code=1;result=None
            writer_ctor.assert_not_called();journal_ctor.assert_not_called()
            transport.assert_not_called();revoke.assert_not_called();isolate.assert_not_called()
            self.assertIsNone(ctx['writer'])
            return code,result,diagnostic.call_count

    def blocked(self,**kw):
        code,result,calls=self.route(**kw)
        self.assertEqual((code,result,calls),(1,None,0))

    def test_absent_and_empty_manifest_bootstrap(self):
        for manifest in (None,''):
            for inputs in ({},{'proposal':'','proof_operation':''}):
                with self.subTest(manifest=manifest,inputs=inputs):
                    code,result,calls=self.route(inputs=inputs,manifest=manifest)
                    self.assertEqual((code,calls),(0,1));self.assertEqual(result['phase'],'SETUP_BOOTSTRAP')

    def test_absent_manifest_nonempty_proposal_blocked(self):
        self.blocked(inputs={'proposal':w._canonical(PLAN['faults'][pc.FAULTS[0]]['proposal']).decode()})

    def test_absent_manifest_proof_operations_blocked(self):
        for op in (*pc.FAULTS,pc.OUTAGE):
            with self.subTest(op=op):self.blocked(inputs={'proof_operation':op})

    def test_historical_manifest_empty_blocked(self):
        self.blocked(manifest=json.dumps({'runtime_variant':'r3c','frozen':True}))

    def test_malformed_manifest_empty_blocked(self):
        for value in ('{','invalid',' ','[]','false','0'):
            self.blocked(manifest=value)

    def test_json_null_manifest_empty_blocked(self):
        self.blocked(manifest='null')

    def test_unfrozen_manifest_empty_blocked(self):
        self.blocked(manifest=json.dumps({'runtime_variant':'r3e','frozen':False}))

    def test_frozen_manifest_empty_blocked(self):
        self.blocked(manifest=json.dumps(manifest(Git())))

    def test_malformed_proposal_or_operation_blocked(self):
        for inputs in ({'proposal':None},{'proposal':{}},{'proposal':' '},{'proposal':'{broken'},
                       {'proof_operation':None},{'proof_operation':[]},{'proof_operation':'UNKNOWN'}):
            with self.subTest(inputs=inputs):self.blocked(inputs=inputs)

    def test_no_public_bootstrap_or_api_controls(self):
        for key in ('setup','bootstrap','method','url','body','endpoint','repository','ref','path','journal','duration'):
            with self.subTest(key=key):self.blocked(inputs={key:'chosen'})

    def test_bootstrap_no_writer_journal_transport_or_faults(self):
        code,result,calls=self.route()
        self.assertEqual((code,calls),(0,1))  # route instruments every forbidden entry.
        self.assertFalse(result['journal_mutation_attempted']);self.assertFalse(result['proof_consumption_attempted'])

    def test_bootstrap_result_not_acceptance_or_frozen(self):
        _,r,_=self.route()
        self.assertIs(r['acceptance_credit'],False);self.assertIs(r['frozen'],False)
        self.assertIsNone(r['manifest_sha256']);self.assertIs(r['update_attempted'],False)
        self.assertEqual(r['remote_outcome'],'not_attempted')
        self.assertEqual((r['run_id'],r['run_attempt'],r['runtime_sha']),(50,1,'a'*40))
        self.assertEqual(r['proof_plan_sha256'],PD);self.assertEqual(r['repository'],w.REPO)
        self.assertNotIn('offline-token',json.dumps(r))

    def test_wrong_repository_event_runner_attempt_blocked(self):
        for key,value in [('GITHUB_REPOSITORY','other/repo'),('GITHUB_REPOSITORY_ID','2'),
                          ('GITHUB_EVENT_NAME','push'),('RUNNER_ENVIRONMENT','self-hosted'),('GITHUB_RUN_ATTEMPT','2')]:
            with self.subTest(key=key):self.blocked(env_change={key:value})

    def test_wrong_runtime_ref_sha_workflow_blocked(self):
        for key,value in [('GITHUB_REF',ar.RUNTIME_REF+'-lookalike'),('GITHUB_SHA','b'*40),
                          ('GITHUB_WORKFLOW_REF',w.REPO+'/other.yml@'+ar.RUNTIME_REF)]:
            with self.subTest(key=key):self.blocked(env_change={key:value})

    def test_build_mismatch_before_diagnostics(self):
        original=Path.read_bytes
        def corrupt(path):
            return b'corrupt' if path.name=='writer.py' else original(path)
        with patch.object(Path,'read_bytes',corrupt):self.blocked()

    def test_plan_mismatch_before_diagnostics(self):
        with patch.object(pc,'plan',return_value=(PLAN,'0'*64)):self.blocked()

    def test_environment_identity_and_policy_mismatch_blocked(self):
        for change in ('id','admin','policy','extra'):
            def wrong(path):
                obj=self.metadata(path)
                if path.endswith('/environments/proof6-writer'):
                    if change=='id':obj['id']=0
                    if change=='admin':obj['can_admins_bypass']=True
                if path.endswith('deployment-branch-policies'):
                    if change=='policy':obj['branch_policies'][0]['name']='proof6-writer-runtime-r3c'
                    if change=='extra':obj['total_count']=2
                return obj
            with self.subTest(change=change):self.blocked(get=wrong)

    def test_final_manifest_required_for_normal_and_proof(self):
        for value in ('null','{}','{"frozen":false,"runtime_variant":"r3e"}'):
            for inp in ({'proposal':'{}'},{'proof_operation':pc.FAULTS[0]}):
                with self.subTest(value=value,inp=inp):self.blocked(inputs=inp,manifest=value)

    def test_manifest_removal_never_produces_interval_continuation(self):
        self.blocked(manifest=json.dumps(manifest(Git())))
        _,result,_=self.route(manifest='')
        self.assertIsNone(result['manifest_sha256']);self.assertFalse(result['frozen'])
        self.assertFalse(result['acceptance_credit']);self.assertFalse(result['update_attempted'])

    def test_standalone_diagnostic_fixed_gets_only(self):
        bindings=json.loads((ROOT/'proofs/proof6/diagnostic-bindings.json').read_bytes())
        replies=[dict(total_count=1,repositories=[dict(id=w.REPO_ID,full_name=w.REPO,private=False)])]+bindings['authority_views']
        seen=[]
        def opened(request,timeout):
            seen.append(request.full_url)
            self.assertEqual(request.method,'GET');self.assertIsNone(request.data)
            self.assertEqual(request.get_header('Authorization'),'Bearer offline-token')
            return contextlib.nullcontext(Mock(read=lambda n:w._canonical(replies[len(seen)-1])))
        with patch.object(w.urllib.request,'build_opener',return_value=Mock(open=opened)), \
             patch.object(w,'_Writer',side_effect=AssertionError('NO_WRITER')), \
             patch.object(j,'Journal',side_effect=AssertionError('NO_JOURNAL')):
            r=w.setup_bootstrap_diagnostics(installation_token='offline-token',action_installation_id=str(w.INSTALLATION),action_app_slug='mc-proof-6-gate-writer')
        self.assertEqual(seen,['https://api.github.com/installation/repositories?per_page=100',
                              'https://api.github.com/repos/'+w.REPO+'/rulesets/22725068',
                              'https://api.github.com/repos/'+w.REPO+'/rulesets/22725076'])
        self.assertEqual(r['result'],'APP_AUTH_SETUP_VERIFIED')
        self.assertFalse(r['effective_admin_permission_verified']);self.assertFalse(r['writer_key_isolation_verified'])
        self.assertNotIn('offline-token',json.dumps(r))

    def test_diagnostic_has_no_general_api_arguments(self):
        import inspect
        self.assertEqual(set(inspect.signature(w.setup_bootstrap_diagnostics).parameters),
                         {'installation_token','action_installation_id','action_app_slug'})
        with self.assertRaises(TypeError):w.setup_bootstrap_diagnostics(method='PATCH',path='/other')

    def test_unchanged_accepted_architecture(self):
        for path in ('proofs/proof1/replay.py','proofs/proof2/gate.py','proofs/proof6/admission.py',
                     'proofs/proof6/reconcile.py','proofs/proof6/outage.py','proofs/proof6/diagnostic-bindings.json'):
            before=subprocess.check_output(['git','-C',str(ROOT),'show',
                                           '35c3ea5eff822dc6e4dc1e8f5e0b6f76f0d632e5:'+path])
            self.assertEqual(before,(ROOT/path).read_bytes(),path)

    def test_workflow_preserves_normal_credential_boundary(self):
        source=(ROOT/'.github/workflows/proof6-writer.yml').read_text()
        self.assertIn('environment: proof6-writer',source)
        self.assertIn('contents: read',source);self.assertIn('actions: read',source)
        self.assertIn('PROOF6_D03_JOB_TOKEN: ${{ github.token }}',source)
        self.assertIn('PROOF6_APP_TOKEN: ${{ steps.app-token.outputs.token }}',source)


class R3e(Candidate):
    def job_message(self, binding):
        context = dict(repository=w.REPO,repository_id=str(w.REPO_ID),ref=jt.RUNTIME,
                       workflow_ref=jt.WORKFLOW,sha=binding['runtime_sha'],run_id=str(binding['run_id']),
                       run_attempt=str(binding['run_attempt']),event_name='workflow_dispatch')
        return dict(jobId='11111111-1111-1111-1111-111111111111',
                    variables={'system.github.job':{'value':'writer'},
                        'system.github.token.permissions':{'value':json.dumps(jt.PERMISSIONS)},
                        'system.github.token':{'value':'***','isSecret':True}},
                    contextData={'github':{'t':2,'d':[{'k':k,'v':v} for k,v in context.items()]}})

    def log(self, message):
        return ('[2026-09-11 00:00:00Z INFO Worker] Version: 2.333.0\n'
                '[2026-09-11 00:00:00Z INFO Worker] Commit: '+'f'*40+'\n'
                '[2026-09-11 00:00:01Z INFO Worker] Job message:\n '+json.dumps(message)+'\n').encode()

    def d03(self, status=403, body=None, env_change=None, mutate=None, log_error=None):
        self.g.expected_token='offline-job-token';self.g.status=status
        self.g.error_body=w._canonical({'message':dr.MESSAGE,'status':'403'}) if body is None else body
        obj=writer(self.g,op=pc.FAULTS[1])
        env=dict(GH_TOKEN='offline-job-token',PROOF6_D03_JOB_TOKEN='offline-job-token')
        env.update(env_change or {})
        def current_log():
            self.assertEqual(self.g.row(self.g.refs[j.REF])['type'],'SEND_ARMED')
            self.assertIsNotNone(obj._journal._permit)
            self.assertIsNone(obj._transport_candidate)
            self.assertEqual(self.g.authority_sends,0)
            if log_error:raise log_error
            b=obj._journal.pending[obj._last_evidence['pending_record']]['binding']
            msg=self.job_message(b)
            if mutate:mutate(msg)
            return self.log(msg)
        output=io.StringIO()
        with patch.dict(os.environ,env,clear=True),patch.object(jt,'_worker_log',side_effect=current_log), \
             patch.object(w.http.client,'HTTPSConnection',self.g.connection),contextlib.redirect_stdout(output):
            result=obj.commit_transition(w._canonical(PLAN['faults'][pc.FAULTS[1]]['proposal']),pc.FAULTS[1])
        self.output=output.getvalue()
        return obj,result

    def unresolved(self, result, sends):
        self.assertEqual(result['d03_result'],'FAIL')
        self.assertNotIn('terminal_record',result)
        self.assertEqual(self.g.authority_sends,sends)
        fresh=j.Journal(writer(self.g,51))
        self.assertIn(pc.FAULTS[1],fresh.used)
        with self.assertRaises(ValueError):fresh.recover(lambda:w.BASELINE)
        self.assertTrue(fresh.armed - fresh.resolved)

    def test_successor_plan_and_real_gate_roadmap6(self):
        self.assertEqual(pc.FAULTS[1],'D03_REMOTE_REJECTION')
        self.assertEqual(PLAN['baseline']['roadmap'],6)
        self.assertEqual(PLAN['baseline']['authority'],w.BASELINE)
        for op,entry in PLAN['faults'].items():
            proposal=entry['proposal']
            self.assertEqual(len(proposal),7)
            self.assertEqual(proposal['expected_state_sha256'],PLAN['baseline']['state_sha256'])
            decision=self.w._gate.decide(HISTORY,proposal)
            self.assertEqual(decision['decision'],'ALLOW')
            self.assertEqual(decision['candidate_event']['data']['position'],7)
        with self.assertRaises(ValueError):pc.request({'proof_operation':'D03_REVOKE_CURRENT_TOKEN'})
        for file in ('writer.py','journal.py','proof_control.py','proof_plan.json'):
            self.assertNotIn('D03_REVOKE_CURRENT_TOKEN',(ROOT/'proofs/proof6'/file).read_text())

    def test_missing_job_token_before_permit_and_transport(self):
        obj,r=self.d03(env_change={'PROOF6_D03_JOB_TOKEN':''})
        self.unresolved(r,0);self.assertIsNotNone(obj._journal._permit)
        self.assertIsNone(obj._transport_candidate)

    def test_job_token_provenance_mismatch(self):
        _,r=self.d03(env_change={'PROOF6_D03_JOB_TOKEN':'wrong'})
        self.unresolved(r,0)

    def test_app_token_alias_cannot_substitute(self):
        obj,r=self.d03(env_change={'PROOF6_D03_JOB_TOKEN':'offline-token','GH_TOKEN':'offline-token'})
        self.unresolved(r,0);self.assertIsNotNone(obj._journal._permit)

    def test_unverified_permission_source_blocks(self):
        _,r=self.d03(log_error=OSError('worker log unavailable'))
        self.unresolved(r,0)

    def test_missing_effective_permissions_blocks(self):
        _,r=self.d03(mutate=lambda m:m['variables'].pop('system.github.token.permissions'))
        self.unresolved(r,0)

    def test_contents_write_blocks_before_transport(self):
        _,r=self.d03(mutate=lambda m:m['variables']['system.github.token.permissions'].update(
            value=json.dumps(dict(jt.PERMISSIONS,Contents='write'))))
        self.unresolved(r,0)

    def test_unknown_or_other_write_permissions_block(self):
        for perms in (dict(jt.PERMISSIONS,Actions='write'),dict(jt.PERMISSIONS,Issues='read'),{},
                      dict(jt.PERMISSIONS,Contents=True)):
            self.g=Git()
            _,r=self.d03(mutate=lambda m:m['variables']['system.github.token.permissions'].update(value=json.dumps(perms)))
            self.unresolved(r,0)

    def test_wrong_run_attempt_runtime_repository_or_job_block(self):
        for key in ('run_id','run_attempt','sha','repository_id','ref','workflow_ref','event_name'):
            self.g=Git()
            def mutate(m):
                next(e for e in m['contextData']['github']['d'] if e['k']==key)['v']='wrong'
            _,r=self.d03(mutate=mutate);self.unresolved(r,0)
        self.g=Git()
        _,r=self.d03(mutate=lambda m:m['variables']['system.github.job'].update(value='other'))
        self.unresolved(r,0)

    def test_caller_cannot_choose_source_permission_endpoint_or_token(self):
        for key in ('token','credential','permission','permissions','credential_source','endpoint','force'):
            with self.assertRaises(ValueError):pc.request({'proof_operation':pc.FAULTS[1],key:'x'})
            p=dict(PLAN['faults'][pc.FAULTS[1]]['proposal'],**{key:'x'})
            self.assertFalse(self.w._gate.valid_proposal(p))

    def test_exact_rejection_finalizes_immediately_and_stops(self):
        obj,r=self.d03()
        self.assertEqual(r['d03_result'],'PASS');self.assertEqual(self.g.authority_sends,1)
        rows=[row['type'] for _,row in obj._journal.rows]
        self.assertEqual(rows,['CONSUMED','PENDING','SEND_ARMED','TERMINAL'])
        terminal=self.g.row(obj._journal.head)
        self.assertEqual((terminal['disposition'],terminal['evidence']),('NOT_COMMITTED','FINAL_REJECTION'))
        receipt=terminal['d03'];self.assertEqual(receipt['payload']['force'],False)
        self.assertEqual(receipt['endpoint'],dr.URL);self.assertEqual(receipt['candidate'],r['candidate_commit'])
        j.Journal(writer(self.g,51)).recover(lambda:w.BASELINE)
        self.assertNotIn('offline-job-token',self.output);self.assertNotIn('offline-token',self.output)
        self.assertFalse(any('installation/token' in path for _,path,_ in self.g.calls))

    def test_request_id_optional_but_recorded_when_present(self):
        self.g.headers['x-github-request-id']=None
        obj,r=self.d03();self.assertEqual(r['d03_result'],'PASS')
        self.assertIsNone(self.g.row(obj._journal.head)['request_id'])

    def test_unrelated_403_fails(self):
        _,r=self.d03(body=b'{"message":"Forbidden"}')
        self.unresolved(r,1)

    def test_all_nonqualifying_http_statuses_fail(self):
        for status in (301,400,401,404,409,422,429,500):
            with self.subTest(status=status):
                self.g=Git();_,r=self.d03(status=status);self.unresolved(r,1)

    def test_contradictory_malformed_duplicate_oversized_bodies_fail(self):
        for body in (b'{}',b'null',b'{',b'x'*4097,b'{"message":"Resource not accessible by integration","status":"401"}',
                     b'{"message":"Resource not accessible by integration","errors":[]}',
                     b'{"message":"Resource not accessible by integration","message":"Resource not accessible by integration"}',
                     b'{"message":"Resource not accessible by integration","status":403}',
                     b'{"message":"Resource not accessible by integration","documentation_url":"https://other"}'):
            with self.subTest(body=body[:80]):
                self.g=Git();_,r=self.d03(body=body);self.unresolved(r,1)

    def test_rate_limit_or_invalid_request_id_cannot_qualify(self):
        for key,value in (('x-ratelimit-remaining','0'),('retry-after','60'),('x-github-request-id','bad request id')):
            self.g=Git();self.g.headers[key]=value;_,r=self.d03();self.unresolved(r,1)

    def test_local_connection_error_or_timeout_never_final_rejection(self):
        for error in (OSError('DNS'),TimeoutError(),urllib.error.HTTPError('local',403,'local',{},None)):
            self.g=Git()
            self.g.connection=Mock(side_effect=error)
            _,r=self.d03();self.unresolved(r,0)

    def test_lost_response_remains_armed(self):
        original=self.g.connection
        def connection(*a,**kw):
            c=original(*a,**kw);c.getresponse=Mock(side_effect=TimeoutError());return c
        self.g.connection=connection
        _,r=self.d03();self.unresolved(r,1)

    def test_unexpected_2xx_records_committed_and_d03_fails(self):
        obj,r=self.d03(status=200)
        self.assertEqual((r['result'],r['d03_result']),('COMMITTED','FAIL'))
        row=self.g.row(obj._journal.head);self.assertEqual(row['disposition'],'COMMITTED')
        self.assertEqual(self.g.refs[w.REF],r['candidate_commit']);self.assertEqual(self.g.authority_sends,1)

    def test_2xx_without_candidate_does_not_release_old(self):
        self.g.delay=True;_,r=self.d03(status=200);self.unresolved(r,1)

    def test_candidate_wins_even_against_rejection_response(self):
        original=self.g.connection
        def connection(*a,**kw):
            c=original(*a,**kw);send=c.request
            def request(*a,**kw):
                send(*a,**kw);self.g.advance(w.REF,json.loads(kw['body'])['sha'])
            c.request=request;return c
        self.g.connection=connection
        obj,r=self.d03();self.assertEqual((r['result'],r['d03_result']),('COMMITTED','FAIL'))
        self.assertEqual(self.g.row(obj._journal.head)['disposition'],'COMMITTED')

    def test_terminal_failure_crash_keeps_protected_membership(self):
        self.g.crash=('before','TERMINAL')
        with self.assertRaises(Crash):self.d03()
        self.g.crash=None;fresh=j.Journal(writer(self.g,51))
        with self.assertRaises(ValueError):fresh.recover(lambda:w.BASELINE)
        self.assertTrue(fresh.armed - fresh.resolved);self.assertEqual(self.g.authority_sends,1)

    def test_terminal_lost_append_response_exact_child_confirmation(self):
        self.g.ambiguity='child'
        _,r=self.d03();self.assertEqual(r['d03_result'],'PASS');self.assertEqual(self.g.authority_sends,1)
        self.assertEqual(self.g.journal_sends,4)

    def test_terminal_append_old_no_resend_no_old_only_release(self):
        original=self.g.api
        def api(token,method,path,body=None):
            if method=='PATCH' and self.g.row(body['sha'])['type']=='TERMINAL':
                self.g.ambiguity='old'
            return original(token,method,path,body)
        self.g.api=api
        _,r=self.d03();self.g.ambiguity=None;self.unresolved(r,1)

    def test_replay_and_second_patch_rejected(self):
        obj,r=self.d03();self.assertEqual(r['d03_result'],'PASS')
        with self.assertRaises(ValueError):obj._patch(r['candidate_commit'],False,r)
        self.assertEqual(self.g.authority_sends,1)
        fresh=writer(self.g,51,pc.FAULTS[1])
        with contextlib.redirect_stdout(io.StringIO()):
            out=fresh.commit_transition(w._canonical(PLAN['faults'][pc.FAULTS[1]]['proposal']),pc.FAULTS[1])
        self.assertNotIn('gate',out);self.assertEqual(self.g.authority_sends,1)

    def test_journal_revalidates_full_rejection_evidence(self):
        obj,r=self.d03();rows=copy.deepcopy(obj._journal.rows)
        for key,value in (('endpoint','https://other'),('method','POST'),('candidate','b'*40),
                          ('enforcement_unchanged',False)):
            bad=copy.deepcopy(rows);bad[-1][1]['d03'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):j.Journal(writer(self.g,51)).validate(bad)
        for key,value in (('status',401),('consumed',False),('transmitted',False),('body_sha256','0'*64)):
            bad=copy.deepcopy(rows);bad[-1][1]['d03']['response'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):j.Journal(writer(self.g,51)).validate(bad)

    def test_normal_transport_ignores_job_token_and_has_no_selector(self):
        import inspect
        self.assertNotIn('token',inspect.signature(w._Writer._patch).parameters)
        with patch.dict(os.environ,{'GH_TOKEN':'job','PROOF6_D03_JOB_TOKEN':'job'}), \
             patch.object(jt,'bind',side_effect=AssertionError('NORMAL_MUST_NOT_SELECT_JOB_TOKEN')):
            _,r=self.run_writer();self.assertEqual(r['result'],'COMMITTED')

    def test_no_revocation_or_retained_log_recovery_reachable(self):
        self.assertFalse(hasattr(w._Writer,'_revoke_current_token'))
        self.assertFalse(hasattr(dr,'recover'));self.assertFalse(hasattr(dr,'_logs'))
        for file in ('writer.py','journal.py','d03_rejection.py'):
            source=(ROOT/'proofs/proof6'/file).read_text()
            self.assertNotIn("method='DELETE'",source)
            self.assertNotIn('/installation/token',source)

    def test_duplicate_wrong_type_truncated_worker_evidence_rejected(self):
        journal,p,c=self.begin(pc.FAULTS[1]);b=journal.pending[p]['binding'];msg=self.job_message(b)
        raw=self.log(msg)
        for bad in (b'',raw[:150],raw+raw,raw.replace(b'"run_id", "v": "50"',b'"run_id", "v": 50')):
            with self.assertRaises((ValueError,KeyError)):jt._permission_evidence(bad,b)
        self.assertEqual(jt._permission_evidence(raw,b)['permissions'],jt.PERMISSIONS)

    def test_whitespace_or_header_invalid_token_fails_before_transport(self):
        for token in (' ', 'bad\ntoken', 'bad\rtoken', 'bad token'):
            self.g=Git();_,r=self.d03(env_change={'PROOF6_D03_JOB_TOKEN':token,'GH_TOKEN':token})
            self.unresolved(r,0)

    def test_actual_linux_ancestor_and_open_fd_discovery(self):
        # Local process fixture only: copied Python executable named Runner.Worker
        # holds a synthetic diagnostic. No GitHub call, real token, or live runner.
        script='''import pathlib,sys,tempfile,shutil,subprocess,json
root=sys.argv[1]
with tempfile.TemporaryDirectory(prefix='proof6-r3e-offline-') as tmp:
    p=pathlib.Path(tmp);(p/'bin').mkdir();(p/'_diag').mkdir()
    worker=p/'bin/Runner.Worker';shutil.copy2(sys.executable,worker)
    log=p/'_diag/Worker_fixture.log';log.write_bytes(b'OFFLINE_PERMISSION_SOURCE_ONLY')
    child='import sys;sys.path.insert(0,'+repr(root+'/proofs/proof6')+');import d03_job_token as j;assert j._worker_log()==b"OFFLINE_PERMISSION_SOURCE_ONLY";print("CURRENT_WORKER_FD_OK")'
    parent='import subprocess,sys;f=open(sys.argv[1],"rb");subprocess.run([sys.argv[2],"-B","-c",sys.argv[3]],check=True)'
    r=subprocess.run([str(worker),'-B','-c',parent,str(log),sys.executable,child],capture_output=True,text=True,timeout=10)
    assert r.returncode==0,r.stderr
    assert r.stdout.strip()=='CURRENT_WORKER_FD_OK',r.stdout
print('OFFLINE_WORKER_ANCESTRY_OK')
'''
        linux_root='/mnt/'+str(ROOT)[0].lower()+str(ROOT)[2:].replace('\\','/')
        out=subprocess.run(['wsl','-d','Ubuntu-22.04','--','python3','-',linux_root],input=script,
                           text=True,capture_output=True,timeout=30)
        self.assertEqual(out.returncode,0,out.stderr)
        self.assertIn('OFFLINE_WORKER_ANCESTRY_OK',out.stdout)

    def test_launcher_never_credits_unexpected_commit(self):
        env=Bootstrap().context();env['PROOF6_FROZEN_MANIFEST']=json.dumps(manifest(self.g))
        event=json.dumps({'inputs':{'proof_operation':pc.FAULTS[1]}})
        for outcome,credit,exit_code in (('COMMITTED','FAIL',1),('INDETERMINATE','FAIL',1),('ERROR','PASS',0)):
            fake=Mock();fake.commit_transition.return_value=dict(result=outcome,d03_result=credit)
            with patch.dict(os.environ,env,clear=True),patch.object(Path,'read_text',return_value=event), \
                 patch.object(ar,'guard'),patch.object(pc,'qualify',return_value=CALLER), \
                 patch.object(ar,'_Writer',return_value=fake),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ar.main({'writer':None}),exit_code)

    def test_changed_or_unreadable_authority_after_evidence_read(self):
        for outcome in ('candidate','other','unreadable'):
            self.g=Git();original=self.g.api;reads=[0]
            def api(token,method,path,body=None):
                if method=='GET' and path.endswith('/git/ref/heads/proof6-authority') and self.g.authority_sends:
                    reads[0]+=1
                    if reads[0]==2:
                        if outcome=='unreadable':raise OSError('authority unavailable')
                        armed=self.g.row(self.g.refs[j.REF]);pending=self.g.row(armed['pending'])
                        self.g.refs[w.REF]=pending['candidate'] if outcome=='candidate' else 'e'*40
                return original(token,method,path,body)
            self.g.api=api;obj,r=self.d03()
            self.assertEqual(r['d03_result'],'FAIL');self.assertEqual(self.g.authority_sends,1)
            if outcome=='candidate':
                self.assertEqual(r['result'],'COMMITTED')
                self.assertEqual(self.g.row(obj._journal.head)['disposition'],'COMMITTED')
            else:
                self.assertNotIn('terminal_record',r)
                self.assertEqual(self.g.row(self.g.refs[j.REF])['type'],'SEND_ARMED')

    def test_d03_candidate_recovery_without_any_actions_logs(self):
        self.g.crash=('before','TERMINAL')
        with self.assertRaises(Crash):self.d03(status=200)
        self.g.crash=None
        with patch.object(ar,'get',side_effect=AssertionError('NO_ACTIONS_LOG_LOOKUP')), \
             patch.object(jt,'_worker_log',side_effect=AssertionError('NO_WORKER_LOG_RECOVERY')):
            fresh=j.Journal(writer(self.g,51));fresh.recover(lambda:self.g.refs[w.REF])
        self.assertEqual(self.g.row(fresh.head)['disposition'],'COMMITTED')
        self.assertEqual(self.g.authority_sends,1)

    def test_durable_credential_provenance_and_permission_tamper_block(self):
        obj,r=self.d03();rows=copy.deepcopy(obj._journal.rows)
        for key,value in (('source','app-token'),('permissions',dict(jt.PERMISSIONS,Contents='write')),
                          ('binding',dict(rows[-1][1]['d03']['binding'],run_id=99))):
            bad=copy.deepcopy(rows);bad[-1][1]['d03']['credential'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):j.Journal(writer(self.g,51)).validate(bad)


class Framing(R3e):
    BODY = b'{"message":"Resource not accessible by integration","status":"403"}'

    def wire(self, headers, body=None, status=403):
        return ('HTTP/1.1 '+str(status)+' Response\r\n').encode()+headers+(
            b'\r\nx-github-request-id: OFFLINE:REQUEST\r\n\r\n')+(self.BODY if body is None else body)

    def fail_wire(self, headers, body=None):
        self.g=Git();self.g.response_wire=self.wire(headers,body)
        obj,r=self.d03()
        self.unresolved(r,1)
        self.assertIsNot(r.get('response_consumed'),True)
        self.assertNotIn('d03_response',r)
        self.assertNotIn('terminal_record',r)
        with self.assertRaises(ValueError):obj._patch(r['candidate_commit'],False,r)
        self.assertEqual(self.g.authority_sends,1)
        return r

    def test_real_exact_content_length_qualifies_and_replays(self):
        self.g.response_wire=self.wire(b'Content-Length: '+str(len(self.BODY)).encode())
        obj,r=self.d03();self.assertEqual(r['d03_result'],'PASS')
        self.assertIsInstance(self.g.last_response,w.http.client.HTTPResponse)
        receipt=self.g.row(obj._journal.head)['d03']['response']
        self.assertEqual(receipt['declared_body_length'],len(self.BODY))
        self.assertEqual(receipt['consumed_body_length'],len(self.BODY))
        self.assertIs(receipt['response_complete'],True);self.assertIs(receipt['connection_eof'],True)
        j.Journal(writer(self.g,51)).recover(lambda:w.BASELINE)

    def test_real_premature_eof_with_valid_json_prefix_blocks(self):
        self.fail_wire(b'Content-Length: '+str(len(self.BODY)+5).encode())

    def test_real_smaller_declared_length_rejects_excess_bytes(self):
        self.fail_wire(b'Content-Length: '+str(len(self.BODY)-1).encode())
        # A complete qualifying JSON at exactly N, followed by undeclared bytes,
        # must also fail; HTTPResponse.read(N) would otherwise hide that suffix.
        self.fail_wire(b'Content-Length: '+str(len(self.BODY)).encode(),self.BODY+b'x')

    def test_real_duplicate_conflicting_and_identical_lengths_block(self):
        length=str(len(self.BODY)).encode()
        for second in (b'999',length):
            self.fail_wire(b'Content-Length: '+length+b'\r\ncontent-length: '+second)

    def test_real_invalid_negative_overflow_or_folded_lengths_block(self):
        for length in (b'-1',b'+65',b'1.0',b'1e2',b'0x41',b'65,65',b'',b'9'*100,
                       b'5\r\n 7',b'NaN',b'99999'):
            with self.subTest(length=length):self.fail_wire(b'Content-Length: '+length)

    def test_real_oversize_declared_length_blocks_before_body_read(self):
        response=real_response(self.wire(b'Content-Length: 4097'))
        position=response.fp.tell()
        with self.assertRaises(ValueError):w._d03_complete_body(response)
        self.assertEqual(response.fp.tell(),position)
        self.fail_wire(b'Content-Length: 4097')

    def test_real_cl_and_transfer_encoding_always_block(self):
        for encoding in (b'chunked',b'identity',b'gzip'):
            self.fail_wire(b'Content-Length: '+str(len(self.BODY)).encode()+b'\r\nTransfer-Encoding: '+encoding)

    def test_real_complete_incomplete_malformed_chunked_all_unsupported(self):
        valid=hex(len(self.BODY))[2:].encode()+b'\r\n'+self.BODY+b'\r\n0\r\n\r\n'
        for body in (valid,valid[:-4],b'bad-size\r\n'+self.BODY,b'0\r\n'):
            self.fail_wire(b'Transfer-Encoding: chunked',body)

    def test_real_other_conflicting_transfer_encodings_block(self):
        for headers in (b'Transfer-Encoding: gzip',b'Transfer-Encoding: identity',
                        b'Transfer-Encoding: gzip, chunked',
                        b'Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip'):
            self.fail_wire(headers)

    def test_real_unframed_connection_close_is_insufficient(self):
        self.fail_wire(b'Connection: close')

    def test_real_body_size_overflow_and_undeclared_suffix_block(self):
        self.fail_wire(b'Content-Length: 4096',b'x'*4097)
        self.fail_wire(b'Content-Length: 1',b'x'*10000)

    def test_real_framing_success_still_requires_json_and_exact_message(self):
        for body in (b'{',b'{"message":"Forbidden"}'):
            self.g=Git();self.g.response_wire=self.wire(b'Content-Length: '+str(len(body)).encode(),body)
            _,r=self.d03();self.unresolved(r,1)
            self.assertIs(r['response_consumed'],True)  # Framing complete; classifier fails.

    def test_real_reader_bounded_reads_with_partial_delivery(self):
        raw=self.wire(b'Content-Length: '+str(len(self.BODY)).encode())
        response=real_response(raw);source=response.fp;calls=[]
        class Partial:
            def read(inner,n):
                self.assertGreater(n,0);self.assertLessEqual(n,dr.BODY_LIMIT)
                calls.append(n);return source.read(min(n,3))
            def flush(inner):source.flush()
            def close(inner):source.close()
        response.fp=Partial()
        body,evidence=w._d03_complete_body(response)
        self.assertEqual(body,self.BODY);self.assertTrue(evidence['response_complete'])
        self.assertGreater(len(calls),2);self.assertEqual(calls[-1],1)

    def test_real_exact_body_limit_can_qualify(self):
        body=self.BODY+b' '*(dr.BODY_LIMIT-len(self.BODY))
        self.g.response_wire=self.wire(b'Content-Length: 4096',body)
        _,r=self.d03();self.assertEqual(r['d03_result'],'PASS')
        self.assertEqual(r['d03_response']['consumed_body_length'],4096)

    def test_real_read_exception_or_timeout_never_qualifies(self):
        for error in (w.http.client.IncompleteRead(b'prefix',5),TimeoutError(),OSError('read lost')):
            self.g=Git();original=self.g.connection
            def connection(*a,**kw):
                c=original(*a,**kw);get=c.getresponse
                def getresponse():
                    response=get();response.fp=Mock(read=Mock(side_effect=error));return response
                c.getresponse=getresponse;return c
            self.g.connection=connection
            _,r=self.d03();self.unresolved(r,1);self.assertIsNot(r.get('response_consumed'),True)

    def test_real_timeout_waiting_for_close_after_exact_body_blocks(self):
        original=self.g.connection
        def connection(*a,**kw):
            c=original(*a,**kw);get=c.getresponse
            def getresponse():
                response=get();source=response.fp;reads=[0]
                def read(n):
                    reads[0]+=1
                    if reads[0]>1:raise TimeoutError('no connection close')
                    return source.read(n)
                response.fp=Mock(read=read);return response
            c.getresponse=getresponse;return c
        self.g.connection=connection
        _,r=self.d03();self.unresolved(r,1);self.assertIsNot(r.get('response_consumed'),True)

    def test_journal_rejects_missing_or_impossible_completion_evidence(self):
        obj,r=self.d03();rows=copy.deepcopy(obj._journal.rows)
        fields=('response_framing','declared_body_length','consumed_body_length','response_complete','connection_eof')
        for field in fields:
            bad=copy.deepcopy(rows);del bad[-1][1]['d03']['response'][field]
            with self.subTest(missing=field),self.assertRaises(ValueError):j.Journal(writer(self.g,51)).validate(bad)
        for field,value in (('response_framing','chunked'),('response_framing','close'),
                            ('declared_body_length',-1),('declared_body_length',4097),('declared_body_length',True),
                            ('declared_body_length',1),('consumed_body_length',0),('consumed_body_length','65'),
                            ('response_complete',False),('response_complete',1),('connection_eof',False)):
            bad=copy.deepcopy(rows);bad[-1][1]['d03']['response'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):j.Journal(writer(self.g,51)).validate(bad)

    def test_real_200_complete_response_still_committed_d03_fail(self):
        self.g.response_wire=self.wire(b'Content-Length: 0',b'',200)
        obj,r=self.d03(status=200)
        self.assertEqual((r['result'],r['d03_result']),('COMMITTED','FAIL'))
        self.assertEqual(self.g.row(obj._journal.head)['disposition'],'COMMITTED')
        self.assertEqual(self.g.authority_sends,1)

    def test_plan_and_all_other_source_are_v1_byte_identical(self):
        parent='ae20b8e49d353ccb10ddbf491e90b51c14b13acc'
        for path in json.loads((ROOT/'proofs/proof6/build.json').read_bytes()):
            if path in ('proofs/proof6/writer.py','proofs/proof6/d03_rejection.py'):continue
            expected=subprocess.check_output(['git','-C',str(ROOT),'show',parent+':'+path])
            self.assertEqual((ROOT/path).read_bytes(),expected,path)
        self.assertEqual(PD,'fd5af499de268003b8a8a6c9261b7708cb76b718e54222d105011c483711ff1c')


if __name__=='__main__':
    with patch.object(socket,'socket',side_effect=AssertionError('OFFLINE_ONLY')):
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(Candidate)
        suite.addTests(Corrections(name) for name in Corrections.__dict__ if name.startswith('test_'))
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(Bootstrap))
        suite.addTests(R3e(name) for name in R3e.__dict__ if name.startswith("test_"))
        suite.addTests(Framing(name) for name in Framing.__dict__ if name.startswith("test_"))
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(not result.wasSuccessful())
