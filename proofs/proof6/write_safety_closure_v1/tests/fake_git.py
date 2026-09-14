"""Inert accepted Git/HTTP fixture adapted only for fresh campaign bindings."""
import base64
import copy
import hashlib
import io
import json
import sys
import urllib.error
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import writer as w
import journal as j
from common import ROOT
HISTORY = json.loads((ROOT / 'proofs/proof6/tests/baseline-history.json').read_bytes())

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
        self.objects['b'*40] = dict(sha='b'*40, tree={'sha':tree}, parents=[])
        self.refs[w.REF] = 'b'*40

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
        assert method=='PATCH' and suffix=='/git/refs/heads/proof6-ws-closure-v1-journal'
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
                assert method=='PATCH' and path==j.BASE+'/git/refs/heads/proof6-ws-closure-v1-authority'
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
