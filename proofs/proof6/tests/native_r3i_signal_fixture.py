"""Linux process/IPC custody model with synthetic credentials and inert HTTP.

The two wrapper files call the production signal boundary under its fixed argv.
They do NOT run the authority writer or isolate a namespace. No GitHub request,
protected state, D04 consumption or acceptance evidence is possible here.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT/'proofs/proof6/d04_signal.py'
PUBLIC = {'GITHUB_REPOSITORY':'flipjam/mc-proof6-synthetic-20260909',
    'GITHUB_REPOSITORY_ID':'1363510385', 'GITHUB_REF':'refs/heads/proof6-writer-runtime-r3i',
    'GITHUB_WORKFLOW_REF':'flipjam/mc-proof6-synthetic-20260909/.github/workflows/proof6-writer.yml@refs/heads/proof6-writer-runtime-r3i',
    'GITHUB_SHA':'a'*40, 'GITHUB_RUN_ATTEMPT':'1', 'GITHUB_EVENT_NAME':'workflow_dispatch',
    'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8'}
LOAD = f"""import importlib.util,sys,os,time,socket
spec=importlib.util.spec_from_file_location('signal_production',{str(SOURCE)!r})
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
# Every INET socket is forbidden, including accidental unmocked HTTP.
original_socket=socket.socket
def unix_only(family=socket.AF_INET,*args,**kwargs):
    assert family==socket.AF_UNIX,'OFFLINE_ONLY'
    return original_socket(family,*args,**kwargs)
socket.socket=unix_only
"""


class Native(unittest.TestCase):
    serial=0

    def setUp(self):
        self.assertEqual(os.geteuid(),0,'Run this offline fixture as WSL root; no sudo password needed.')
        type(self).serial+=1
        self.run=str(9000000000+os.getpid()*10+self.serial)
        self.env=dict(PUBLIC,GITHUB_RUN_ID=self.run)
        self.root=Path('/tmp')/('proof6-d04-signal-'+self.run+'-1-'+'a'*40)
        self.assertFalse(self.root.exists());self.root.mkdir(mode=0o700)
        self.temp=Path(tempfile.mkdtemp(prefix='proof6-r3i-offline-'))
        self.scripts=self.temp/'proofs/proof6';self.scripts.mkdir(parents=True)
        self.procs=[];self.files=[]
        self.null=Path('/dev/null').open('rb');self.files.append(self.null)

    def tearDown(self):
        for proc in self.procs:
            if proc.poll() is None:
                proc.kill();proc.wait(timeout=5)
        for stream in self.files:stream.close()
        for path in (self.root,self.temp):
            self.assertEqual(path.parent,Path('/tmp'))
            self.assertTrue(path.name.startswith(('proof6-d04-signal-','proof6-r3i-offline-')))
            shutil.rmtree(path)

    def wrappers(self, preflight_failure=False, no_end=False):
        self.helper=self.scripts/'d04_signal.py'
        self.helper.write_text(LOAD+f"""
s._worker_log=lambda:b''
s._permission_evidence=lambda raw,b:dict(permissions=s.PERMISSIONS,binding=b,offline_model=True)
def provider(token,b,event=None):
    assert token=='STATUS_SENTINEL'
    if {preflight_failure!r}:raise ValueError('OFFLINE_PROVIDER_FAILURE')
    return dict(http_status=200 if event is None else 201,payload=None,
                started_at=s.utc(),completed_at=s.utc(),date=None,request_id=None)
s.status_request=provider
try:
    s.serve() if sys.argv[1:]==['serve'] else s.cleanup()
except BaseException as e:
    s.receipt('BLOCKED',exception=type(e).__name__,acceptance_credit=False)
    sys.exit(1)
""")
        self.writer=self.scripts/'actions_runtime.py'
        self.writer.write_text(LOAD+f"""
sys.path.insert(0,{str(ROOT/'proofs/proof6/tests')!r})
from d04_fixtures import child
try:
    client=s.Client()
    record=child();record['context']['pid']=os.getpid()
    record['context']['netns']='net:[1]'
    record['netns_after']=os.readlink('/proc/self/ns/net')
    client.emit(dict(phase='READY',observation=record))
    if not {no_end!r}:
        time.sleep(30)
        client.emit(dict(phase='END',observation=record))
    client.close()
except BaseException as e:
    s.receipt('BLOCKED',exception=type(e).__name__,acceptance_credit=False)
    sys.exit(1)
""")

    def start(self, extra=None):
        # Native timeout is the real parent/reaper, as in the workflow.
        logfile=(self.root/'helper.log').open('wb');self.files.append(logfile)
        env=dict(self.env,PROOF6_D04_STATUS_TOKEN='STATUS_SENTINEL');env.update(extra or {})
        proc=subprocess.Popen(['/usr/bin/timeout','--signal=KILL','120s','/usr/bin/python3',
            '-I','-B','proofs/proof6/d04_signal.py','serve'],cwd=self.temp,env=env,
            stdin=self.null,stdout=logfile,stderr=logfile,close_fds=True)
        self.procs.append(proc);self.native=proc
        (self.root/'native.pid').write_text(str(proc.pid))
        until=time.monotonic()+8
        while not (self.root/'started.json').exists() and proc.poll() is None and time.monotonic()<until:
            time.sleep(.05)
        return (self.root/'started.json').exists()

    def producer(self, extra=None, fd=False, argv=False):
        env=dict(self.env,PROOF6_APP_TOKEN='APP_SENTINEL');env.update(extra or {})
        command=['/usr/bin/python3','-B','proofs/proof6/actions_runtime.py']
        if argv:command.append('STATUS_SENTINEL')
        inherited=()
        if fd:
            handle=(self.temp/'synthetic-credential').open('wb+');self.files.append(handle)
            handle.write(b'SYNTHETIC_ONLY');handle.flush();inherited=(handle.fileno(),)
        proc=subprocess.Popen(command,cwd=self.temp,env=env,stdin=self.null,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,pass_fds=inherited)
        self.procs.append(proc)
        out,err=proc.communicate(timeout=45)
        self.assertNotIn(b'APP_SENTINEL',out+err);self.assertNotIn(b'STATUS_SENTINEL',out+err)
        return proc.returncode,out

    def reap(self, terminate=False):
        if terminate and self.native.poll() is None:self.native.terminate()
        rc=self.native.wait(timeout=8)
        (self.root/'reaped.exit').write_text(str(rc))
        if (self.root/'started.json').exists():
            pid=json.loads((self.root/'started.json').read_bytes())['pid']
            self.assertFalse(Path('/proc',str(pid)).exists())
        raw=(self.root/'helper.log').read_bytes()
        self.assertNotIn(b'APP_SENTINEL',raw);self.assertNotIn(b'STATUS_SENTINEL',raw)
        return rc,raw

    def test_ready_end_30_seconds_custody_and_reaping(self):
        self.wrappers();self.assertTrue(self.start(),(self.root/'helper.log').read_text())
        rc,out=self.producer();self.assertEqual(rc,0,out.decode())
        rc,raw=self.reap();self.assertEqual(rc,0,raw.decode())
        rows=[json.loads(line.split(b' ',1)[1]) for line in raw.splitlines() if line.startswith(b'PROOF6_D04_SIGNAL ')]
        events=[x['event'] for x in rows if x['kind']=='STATUS_POST']
        self.assertEqual([e['phase'] for e in events],['READY','END'])
        self.assertGreaterEqual(events[1]['monotonic']-events[0]['monotonic'],30)
        p=subprocess.run(['/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py','cleanup'],
            cwd=self.temp,env=self.env,capture_output=True,timeout=12)
        self.assertEqual(p.returncode,0,p.stdout.decode());self.assertIn(b'HELPER_REAPED',p.stdout)

    def test_helper_app_receipt_fails_before_readiness(self):
        self.wrappers();self.assertFalse(self.start({'PROOF6_APP_TOKEN':'APP_SENTINEL'}))
        rc,raw=self.reap();self.assertNotEqual(rc,0);self.assertNotIn(b'STATUS_POST',raw)

    def test_provider_preflight_failure_blocks_startup(self):
        self.wrappers(preflight_failure=True);self.assertFalse(self.start())
        rc,raw=self.reap();self.assertNotEqual(rc,0);self.assertNotIn(b'STATUS_POST',raw)

    def test_writer_status_receipt_fails_and_helper_reaped(self):
        self.wrappers();self.assertTrue(self.start(),(self.root/'helper.log').read_text())
        rc,_=self.producer({'PROOF6_D04_STATUS_TOKEN':'STATUS_SENTINEL'});self.assertNotEqual(rc,0)
        rc,raw=self.reap(terminate=True);self.assertNotEqual(rc,0);self.assertNotIn(b'STATUS_POST',raw)

    def test_inherited_descriptor_fails_and_helper_reaped(self):
        self.wrappers();self.assertTrue(self.start(),(self.root/'helper.log').read_text())
        rc,_=self.producer(fd=True);self.assertNotEqual(rc,0)
        rc,raw=self.reap(terminate=True);self.assertNotEqual(rc,0);self.assertNotIn(b'STATUS_POST',raw)

    def test_missing_end_never_completes(self):
        self.wrappers(no_end=True);self.assertTrue(self.start(),(self.root/'helper.log').read_text())
        self.assertEqual(self.producer()[0],0)
        rc,raw=self.reap();self.assertNotEqual(rc,0)
        self.assertIn(b'"phase": "READY"',raw);self.assertNotIn(b'"phase": "END"',raw)

    def test_production_cleanup_terminates_and_confirms_reaping(self):
        self.wrappers();self.assertTrue(self.start(),(self.root/'helper.log').read_text())
        def waiter():
            (self.root/'reaped.exit').write_text(str(self.native.wait(timeout=15)))
        thread=threading.Thread(target=waiter);thread.start()
        proc=subprocess.run(['/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py','cleanup'],
            cwd=self.temp,env=self.env,capture_output=True,timeout=12)
        thread.join(timeout=2);self.assertFalse(thread.is_alive())
        self.assertEqual(proc.returncode,1)
        self.assertIn(b'HELPER_REAPED',proc.stdout)
        self.assertIn(b'"interrupted": true',proc.stdout)
        self.reap()


if __name__=='__main__':
    unittest.main(verbosity=2)
