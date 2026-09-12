"""Real Linux recvmsg/sendmsg and setup processes; no provider execution.

WSL1 is not native Linux and does not implement these zero-length recvmsg
semantics correctly. Run on native Linux/WSL2, with root for custody fixtures.
"""
import array
import errno
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import d04_signal as s
import native_r3i_signal_fixture as n
from d04_fixtures import child

B = dict(run_id=123, attempt=1, runtime_sha='a'*40, target_sha='a'*40,
         context='proof6/d04-signal/123/1/'+'a'*40)


def event(phase='READY'):
    record = child()
    return dict(schema=s.SCHEMA, binding=B, pid=record['context']['pid'], phase=phase,
                monotonic=time.monotonic(), utc=s.utc(), observation=record)


class Packets(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(self.a.close); self.addCleanup(self.b.close)
        self.a.settimeout(1)

    def rights(self, payload, count=1, capacity=None, shutdown=False):
        original = os.open('/dev/null', os.O_RDONLY)
        self.addCleanup(os.close, original)
        before = set(os.listdir('/proc/self/fd'))
        self.b.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [original]*count))])
        closed = []
        real_close = os.close
        def close(fd):
            closed.append(fd); real_close(fd)
        with patch.object(s, 'CONTROL_BYTES', s.CONTROL_BYTES if capacity is None else capacity), patch.object(s.os, 'close', side_effect=close):
            with self.assertRaises(ValueError):
                s.peer_shutdown(self.a) if shutdown else s.receive(self.a)
        self.assertGreater(len(closed), 0)
        for fd in closed:
            with self.assertRaises(OSError) as caught: os.fstat(fd)
            self.assertEqual(caught.exception.errno, errno.EBADF)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)
        return closed

    def test_canonical_no_ancillary_passes_actual_boundary(self):
        value=event();s.packet(self.b,value)
        received=s.receive(self.a)
        s.event_valid(received,B,value['pid'],'READY')
        self.assertEqual(received,value)

    def test_reviewer_A_ready_with_rights_rejected(self):
        self.assertEqual(len(self.rights(s.canonical(event()))),1)

    def test_end_with_rights_rejected(self):
        self.rights(s.canonical(event('END')))

    def test_multiple_descriptors_all_closed(self):
        self.assertEqual(len(self.rights(s.canonical(event()),16)),16)

    def test_linux_maximum_253_descriptors_all_closed(self):
        self.assertEqual(len(self.rights(s.canonical(event()),253)),253)

    def test_unexpected_constructible_credentials_rejected(self):
        self.a.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        self.b.sendmsg([s.canonical(event())],[(socket.SOL_SOCKET,socket.SCM_CREDENTIALS,
            struct.pack('3i',os.getpid(),os.getuid(),os.getgid()))])
        with self.assertRaises(ValueError):s.receive(self.a)

    def test_actual_ancillary_truncation_rejected_and_delivered_fds_closed(self):
        closed=self.rights(s.canonical(event()),16,socket.CMSG_SPACE(4))
        self.assertLess(len(closed),16)

    def test_ctrunc_flag_without_records_rejected(self):
        fd=os.open('/dev/null',os.O_RDONLY);self.addCleanup(os.close,fd)
        self.b.sendmsg([b'{}'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
        with patch.object(s,'CONTROL_BYTES',0),self.assertRaises(ValueError):s.receive(self.a)

    def test_data_truncation_rejected(self):
        self.b.send(b'x'*(s.MAX_PACKET+2))
        with self.assertRaises(ValueError):s.receive(self.a)

    def test_noncanonical_and_duplicate_json_unchanged(self):
        for raw in (b'{ "a":1}',b'{"a":1,"a":2}',b'garbage',b''):
            self.b.send(raw)
            with self.assertRaises((ValueError,UnicodeError)):s.receive(self.a)

    def complete(self, trailing=None, close=True):
        for phase in ('READY','END'):
            value=event(phase);s.packet(self.b,value);self.assertEqual(s.receive(self.a),value)
        if trailing is not None:self.b.send(trailing)
        if close:self.b.close()
        s.peer_shutdown(self.a)

    def test_expected_protocol_and_genuine_close_pass(self):self.complete()

    def test_expected_protocol_and_genuine_write_shutdown_pass(self):
        self.b.shutdown(socket.SHUT_WR);s.peer_shutdown(self.a)

    def test_reviewer_B_open_empty_packet_rejected(self):
        with self.assertRaises(ValueError):self.complete(b'',False)

    def test_empty_packet_then_close_rejected(self):
        with self.assertRaises(ValueError):self.complete(b'')

    def test_trailing_nonempty_packet_rejected(self):
        with self.assertRaises(ValueError):self.complete(b'x')

    def test_duplicate_ready_rejected(self):
        with self.assertRaises(ValueError):self.complete(s.canonical(event()))

    def test_duplicate_end_rejected(self):
        with self.assertRaises(ValueError):self.complete(s.canonical(event('END')))

    def test_malformed_trailing_packet_rejected(self):
        with self.assertRaises(ValueError):self.complete(b'{broken')

    def test_empty_trailing_rights_closed_and_rejected(self):
        self.rights(b'',3,shutdown=True)

    def test_writer_close_rejects_trailing_helper_empty_packet(self):
        client=object.__new__(s.Client);client.socket=self.a;client.ended=True
        self.b.send(b'');self.b.close()
        with self.assertRaises(ValueError):client.close()
        self.assertEqual(self.a.fileno(),-1)
        client.close()  # Failure cleanup is idempotent.

    def test_open_idle_peer_cannot_satisfy_completion(self):
        self.a.settimeout(.01)
        # Use the real receive/poll boundary; shrink only its fixed wait in this fixture.
        class Bounded:
            def __getattr__(inner,name):return getattr(self.a,name)
            def settimeout(inner,value):self.a.settimeout(.01)
        with self.assertRaises(TimeoutError):s.peer_shutdown(Bounded())


class Setup(unittest.TestCase):
    serial=100
    setUp=n.Native.setUp
    tearDown=n.Native.tearDown
    reap=n.Native.reap

    def wrappers(self, permissions=None, version=None, bad_ipc=False):
        expected={'repository':s.REPO,'repository_id':'1363510385','ref':s.RUNTIME,
            'workflow_ref':s.REPO+'/.github/workflows/proof6-writer.yml@'+s.RUNTIME,
            'sha':'a'*40,'run_id':self.run,'run_attempt':'1','event_name':'workflow_dispatch'}
        message={'variables':{'system.github.token.permissions':{'value':json.dumps(s.PERMISSIONS if permissions is None else permissions)},
            'system.github.job':{'value':'signal_setup'}},'contextData':{'github':{'t':2,'d':[{'k':k,'v':v} for k,v in expected.items()]}},
            'jobId':'12345678-1234-1234-1234-123456789abc'}
        raw=(f'[now INFO Worker] Version: {s.RUNNER_VERSION if version is None else version}\n'
             f'[now INFO Worker] Commit: {s.RUNNER_COMMIT}\n[now INFO Worker] Job message:\n'+json.dumps(message)).encode()
        code=n.LOAD+f'''
import io
s._worker_log=lambda:s.masked_worker_record(io.BytesIO({raw!r}))
def forbidden(*args,**kwargs):raise AssertionError('NO_PROVIDER_CALL_IN_SETUP')
s.status_request=forbidden
if {bad_ipc!r}:
    s.packet=lambda conn,value:conn.send(b'{{broken')
try:
    {{'serve-setup':s.serve_setup,'qualify-setup':s.qualify_setup,'cleanup-setup':lambda:s.cleanup(True)}}[sys.argv[1]]()
except BaseException as error:
    s.receipt('BLOCKED',exception=type(error).__name__,acceptance_credit=False)
    sys.exit(1)
'''
        (self.scripts/'d04_signal.py').write_text(code)

    def start(self,extra=None):
        log=(self.root/'helper.log').open('wb');self.files.append(log)
        env=dict(self.env,PROOF6_D04_STATUS_TOKEN='STATUS_SENTINEL');env.update(extra or {})
        self.native=subprocess.Popen(['/usr/bin/timeout','--signal=KILL','120s','/usr/bin/python3','-I','-B',
            'proofs/proof6/d04_signal.py','serve-setup'],cwd=self.temp,env=env,stdin=self.null,stdout=log,stderr=log,close_fds=True)
        self.procs.append(self.native);(self.root/'native.pid').write_text(str(self.native.pid))
        until=time.monotonic()+8
        while not (self.root/'started.json').exists() and self.native.poll() is None and time.monotonic()<until:time.sleep(.02)
        return (self.root/'started.json').exists()

    def producer(self,extra=None):
        env=dict(self.env);env.update(extra or {})
        proc=subprocess.Popen(['/usr/bin/timeout','--signal=KILL','20s','/usr/bin/python3','-I','-B',
            'proofs/proof6/d04_signal.py','qualify-setup'],cwd=self.temp,env=env,stdin=self.null,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
        self.procs.append(proc);out,err=proc.communicate(timeout=22)
        return proc.returncode,out+err

    def test_real_setup_audit_custody_ipc_shutdown_and_reaping_no_POST(self):
        self.wrappers();self.assertTrue(self.start(),(self.root/'helper.log').read_text())
        rc,out=self.producer();self.assertEqual(rc,0,out.decode())
        rc,raw=self.reap();self.assertEqual(rc,0,raw.decode())
        result=subprocess.run(['/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py','cleanup-setup'],
            cwd=self.temp,env=self.env,capture_output=True,timeout=12)
        self.assertEqual(result.returncode,0,result.stdout.decode())
        with patch.dict(os.environ,self.env,clear=True):
            values=[s.setup_qualification(line.split(b' ',1)[1]) for line in result.stdout.splitlines() if line.startswith(b'PROOF6_SIGNAL_SETUP_OUTPUT ')]
        self.assertEqual(len(values),1);self.assertTrue(values[0]['helper_reaped'] and values[0]['producer_reaped'])
        self.assertEqual(values[0]['status_posts'],0)
        for forbidden in (b'STATUS_POST',b'"phase": "READY"',b'"phase": "END"',b'STATUS_SENTINEL',b'APP_SENTINEL'):
            self.assertNotIn(forbidden,raw+out+result.stdout)

    def test_permission_failure_blocks_setup_before_IPC(self):
        self.wrappers(permissions=dict(s.PERMISSIONS,Contents='read'));self.assertFalse(self.start())
        self.assertNotEqual(self.reap()[0],0)

    def test_unknown_runner_blocks_setup_before_IPC(self):
        self.wrappers(version='0.0.0');self.assertFalse(self.start())
        self.assertNotEqual(self.reap()[0],0)

    def test_helper_App_custody_failure_blocks_setup(self):
        self.wrappers();self.assertFalse(self.start({'PROOF6_APP_TOKEN':'APP_SENTINEL'}))
        self.assertNotEqual(self.reap()[0],0)

    def test_setup_peer_status_custody_failure_blocks(self):
        self.wrappers();self.assertTrue(self.start())
        self.assertNotEqual(self.producer({s.TOKEN_SLOT:'STATUS_SENTINEL'})[0],0)
        self.assertNotEqual(self.reap(terminate=True)[0],0)

    def test_setup_IPC_failure_blocks_and_reaps(self):
        self.wrappers(bad_ipc=True);self.assertTrue(self.start())
        self.assertNotEqual(self.producer()[0],0)
        self.assertNotEqual(self.reap(terminate=True)[0],0)

    def test_setup_without_live_helper_cannot_pass(self):
        self.wrappers();self.assertNotEqual(self.producer()[0],0)


if __name__=='__main__':
    print(json.dumps({'kernel':os.uname().release,'acceptance_credit':False,'hosted_execution':False}),flush=True)
    unittest.main(verbosity=2)
