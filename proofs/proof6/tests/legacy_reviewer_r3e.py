"""Local-only review: real HTTPResponse framing and actual local socket EOF."""
import contextlib,copy,importlib.util,io,json,socket,sys,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).parent
sys.argv=['review',str(ROOT/'candidate')]
s=importlib.util.spec_from_file_location('pub',ROOT/'evidence/test_candidate.py')
t=importlib.util.module_from_spec(s);s.loader.exec_module(t)
BODY=b'{"message":"Resource not accessible by integration","status":"403"}'
def cl(n):return b'Content-Length: '+str(n).encode()+b'\r\n'

class Review(unittest.TestCase):
    def setUp(self):self.h=t.R3e();self.h.setUp()
    def response(self,headers,body=BODY,status=403,live=False,eof=True):
        wire=b'HTTP/1.1 '+str(status).encode()+b' Status\r\nX-GitHub-Request-Id: REVIEW:EOF\r\n'+headers+b'\r\n'+body
        if live:
            a,b=socket.socketpair();a.settimeout(.05);b.sendall(wire)
            if eof:b.shutdown(socket.SHUT_WR)
            self.addCleanup(a.close);self.addCleanup(b.close);sock=a
        else:
            class Sock:
                def makefile(self,*a):return io.BytesIO(wire)
            sock=Sock()
        response=t.w.http.client.HTTPResponse(sock);response.begin();self.addCleanup(response.close)
        return response
    def run_response(self,response,status=403):
        original=self.h.g.connection
        def connect(*a,**kw):
            c=original(*a,**kw);request=c.request
            def send(*a,**kw):
                self.assertEqual(kw['headers']['Connection'],'close')
                self.assertEqual(kw['headers']['Authorization'],'Bearer offline-job-token')
                return request(*a,**kw)
            c.request=send;c.getresponse=lambda:response;return c
        self.h.g.connection=connect
        return self.h.d03(status=status)
    def reject(self,headers,body=BODY,**kw):
        obj,r=self.run_response(self.response(headers,body,**kw));self.blocked(obj,r)
        return obj,r
    def blocked(self,obj,r,framing=True):
        self.assertEqual(r['d03_result'],'FAIL');self.assertNotIn('terminal_record',r)
        if framing:self.assertIsNot(r.get('response_consumed'),True)
        self.assertEqual(self.h.g.authority_sends,1)
        fresh=t.j.Journal(t.writer(self.h.g,1))
        with self.assertRaises(ValueError):fresh.recover(lambda:t.w.BASELINE)
        with patch.object(t.w.http.client,'HTTPSConnection',Mock(side_effect=AssertionError('SECOND_SEND'))),self.assertRaises(ValueError):
            obj._patch(r['candidate_commit'],False,r)
        self.assertEqual(self.h.g.authority_sends,1)
    def valid(self,body=BODY,**kw):
        obj,r=self.run_response(self.response(cl(len(body)),body,**kw))
        self.assertEqual(r['d03_result'],'PASS');self.assertEqual(self.h.g.authority_sends,1)
        response=self.h.g.row(obj._journal.head)['d03']['response']
        self.assertEqual(response['declared_body_length'],len(body));self.assertEqual(response['consumed_body_length'],len(body))
        self.assertIs(response['connection_eof'],True);self.assertIs(response['response_complete'],True)
        t.j.Journal(t.writer(self.h.g,1)).recover(lambda:t.w.BASELINE)
        return obj,r
    def test_01_valid_exact(self):self.valid()
    def test_02_short_body(self):self.reject(cl(len(BODY)+100))
    def test_03_surplus(self):self.reject(cl(len(BODY)-1))
    def test_04_conflicting(self):self.reject(cl(len(BODY))+cl(999))
    def test_05_identical_duplicates(self):self.reject(cl(len(BODY))*2)
    def test_06_invalid_syntax(self):
        for v in (b'+65',b'6.5',b'65,65',b'6e1',b'0x41',b'65\r\n 0'):
            self.h=t.R3e();self.h.setUp();self.reject(b'Content-Length: '+v+b'\r\n')
    def test_07_negative(self):self.reject(cl(-1))
    def test_08_over_limit(self):self.reject(cl(4097))
    def test_09_exact_limit(self):self.valid(BODY+b' '*(4096-len(BODY)))
    def test_10_4097_body(self):self.reject(cl(4096),BODY+b' '*(4097-len(BODY)))
    def test_11_chunked(self):self.reject(b'Transfer-Encoding: chunked\r\n',b'41\r\n'+BODY+b'\r\n0\r\n\r\n')
    def test_12_cl_te(self):self.reject(cl(len(BODY))+b'Transfer-Encoding: identity\r\n')
    def test_13_broken_chunked(self):self.reject(b'Transfer-Encoding: chunked\r\n',b'badchunk\r\n'+BODY)
    def test_14_unframed(self):self.reject(b'Connection: close\r\n')
    def test_15_premature_socket_eof(self):self.reject(cl(len(BODY)+1),live=True)
    def test_16_socket_no_eof(self):self.reject(cl(len(BODY)),live=True,eof=False)
    def test_17_trailing_data(self):self.reject(cl(len(BODY)),BODY+b'HTTP/1.1 200 OK\r\n\r\n')
    def test_18_malformed_json(self):
        obj,r=self.run_response(self.response(cl(1),b'{'));self.blocked(obj,r,False)
        self.assertIs(r['response_consumed'],True)
    def test_19_unrelated_403(self):
        body=b'{"message":"Forbidden"}'
        obj,r=self.run_response(self.response(cl(len(body)),body));self.blocked(obj,r,False)
    def test_20_qualifying_socket_eof(self):self.valid(live=True)
    def test_21_read_failures(self):
        for exc in (TimeoutError(),t.w.http.client.IncompleteRead(b'prefix',100)):
            self.h=t.R3e();self.h.setUp();response=self.response(cl(len(BODY)))
            source=response.fp
            response.fp=Mock(read=Mock(side_effect=exc),close=source.close)
            obj,r=self.run_response(response);self.blocked(obj,r)
    def test_22_missing_completion(self):
        obj,r=self.valid();rows=copy.deepcopy(obj._journal.rows)
        fields=('response_framing','declared_body_length','consumed_body_length','response_complete','connection_eof')
        for field in fields:
            bad=copy.deepcopy(rows);del bad[-1][1]['d03']['response'][field]
            with self.assertRaises(ValueError):t.j.Journal(t.writer(self.h.g,2)).validate(bad)
        bad=copy.deepcopy(rows)
        for field in fields:del bad[-1][1]['d03']['response'][field]
        with self.assertRaises(ValueError):t.j.Journal(t.writer(self.h.g,2)).validate(bad)
    def test_23_contradictory_completion(self):
        obj,r=self.valid();rows=copy.deepcopy(obj._journal.rows)
        for field,value in [('declared_body_length',0),('consumed_body_length',4097),('response_complete',False),('response_complete',1),('connection_eof',False),('response_framing','chunked'),('declared_body_length',True)]:
            bad=copy.deepcopy(rows);bad[-1][1]['d03']['response'][field]=value
            with self.assertRaises(ValueError):t.j.Journal(t.writer(self.h.g,2)).validate(bad)
    def test_24_success_commit(self):
        obj,r=self.run_response(self.response(cl(0),b'',status=200),status=200)
        self.assertEqual((r['result'],r['d03_result']),('COMMITTED','FAIL'))
        self.assertEqual(self.h.g.row(obj._journal.head)['disposition'],'COMMITTED')
        self.assertEqual(self.h.g.authority_sends,1)
    def test_25_no_fallback(self):
        obj,r=self.reject(cl(len(BODY)+1))
        obj._transport_candidate=r['candidate_commit']
        with patch.object(t.w.http.client,'HTTPSConnection',Mock(side_effect=AssertionError('APP_FALLBACK'))),self.assertRaises(ValueError):
            obj._patch(r['candidate_commit'],False,r)
    def test_26_huge_declaration_no_read(self):
        response=self.response(b'Content-Length: '+b'9'*400+b'\r\n')
        before=response.fp.tell()
        with self.assertRaises(ValueError):t.w._d03_complete_body(response)
        self.assertEqual(response.fp.tell(),before)
    def test_27_continuing_stream_bounded(self):
        response=self.response(cl(4096),b'x'*20000);source=response.fp;seen=[]
        class Track:
            def read(self,n):seen.append(n);return source.read(n)
            def close(self):source.close()
            def flush(self):source.flush()
        response.fp=Track()
        with self.assertRaises(ValueError):t.w._d03_complete_body(response)
        self.assertEqual(seen,[4096,1])
    def test_28_fragmented_delivery(self):
        response=self.response(cl(len(BODY)));source=response.fp;seen=[]
        class Fragment:
            def read(self,n):seen.append(n);return source.read(min(1,n))
            def close(self):source.close()
            def flush(self):source.flush()
        response.fp=Fragment();raw,e=t.w._d03_complete_body(response)
        self.assertEqual(raw,BODY);self.assertIs(e['connection_eof'],True)
        self.assertEqual(len(seen),len(BODY)+1)
    def test_29_complete_bad_status(self):
        obj,r=self.run_response(self.response(cl(len(BODY)),status=401),status=401)
        self.blocked(obj,r,False)
    def test_30_socket_excess(self):self.reject(cl(len(BODY)),BODY+b'x',live=True)

if __name__=='__main__':unittest.main(verbosity=2)
