"""Real fixed-argv launch/exec/custody/IPC tests; all INET calls denied."""
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import native_r3i_bounded as prior
import d04_signal as s

EXTRA={'DEBIAN_FRONTEND':'nonsecret'}|{'UNRELATED_%02d'%i:'nonsecret' for i in range(47)}


class Startup(unittest.TestCase):
    serial=300
    setUp=prior.Setup.setUp
    tearDown=prior.Setup.tearDown
    reap=prior.Setup.reap

    def wrappers(self,**kwargs):
        prior.Setup.wrappers(self,**kwargs)
        path=self.scripts/'d04_signal.py';code=path.read_text()
        code=code.replace("{'serve-setup':s.serve_setup,", "{'launch-setup':lambda:s.launch('setup-helper'),'launch-peer':lambda:s.launch('setup-peer'),'serve-setup':s.serve_setup,")
        code=code.replace("{'launch-setup':", "{'launch-writer':lambda:s.launch('writer'),'launch-setup':")
        code=code.replace("s.receipt('BLOCKED',exception=type(error).__name__,acceptance_credit=False)","s.startup_failure(error)")
        path.write_text(code)

    def start(self,extra=None):
        log=(self.root/'helper.log').open('wb');self.files.append(log)
        env=self.env|{s.TOKEN_SLOT:'STATUS_SENTINEL'}|EXTRA|(extra or {})
        self.native=subprocess.Popen(['/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py','launch-setup'],
            cwd=self.temp,env=env,stdin=self.null,stdout=log,stderr=log,close_fds=True)
        self.procs.append(self.native);(self.root/'native.pid').write_text(str(self.native.pid))
        until=time.monotonic()+8
        while not (self.root/'started.json').exists() and self.native.poll() is None and time.monotonic()<until:time.sleep(.02)
        return (self.root/'started.json').exists()

    def producer(self,extra=None):
        proc=subprocess.Popen(['/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py','launch-peer'],
            cwd=self.temp,env=self.env|EXTRA|(extra or {}),stdin=self.null,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
        self.procs.append(proc);out,err=proc.communicate(timeout=22)
        return proc.returncode,out+err

    def test_fixed_launch_passes_real_setup_with_48_extras_no_POST(self):
        self.wrappers();self.assertTrue(self.start(),(self.root/'helper.log').read_text())
        pid=self.native.pid
        argv=Path('/proc',str(pid),'cmdline').read_bytes().split(b'\0')[:-1]
        self.assertEqual(argv[:3],[b'/usr/bin/timeout',b'--signal=KILL',b'120s'])
        rc,out=self.producer();self.assertEqual(rc,0,out.decode())
        rc,raw=self.reap();self.assertEqual(rc,0,raw.decode())
        cleanup=subprocess.run(['/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py','cleanup-setup'],cwd=self.temp,env=self.env,capture_output=True,timeout=12)
        self.assertEqual(cleanup.returncode,0,cleanup.stdout.decode())
        self.assertIn(b'"helper_reaped":true',cleanup.stdout);self.assertIn(b'"producer_reaped":true',cleanup.stdout)
        for forbidden in (b'STATUS_SENTINEL',b'APP_SENTINEL',b'STATUS_POST',b'"phase": "READY"',b'"phase": "END"',b'UNRELATED_',b'DEBIAN_FRONTEND'):
            self.assertNotIn(forbidden,raw+out+cleanup.stdout)
        self.assertFalse(Path('/proc',str(pid)).exists())

    def test_exact_R3h_source_rejects_same_dirty_startup(self):
        # Exact accepted source bytes are retained in the evidence package.
        source=Path(__file__).with_name('r3i-evidence')/'accepted-r3h-source'
        for name in ('d04_signal.py','d04_capability.py'):
            (self.scripts/name).write_bytes((source/name).read_bytes())
        env={k:v.replace('runtime-r3i','runtime-r3h') for k,v in self.env.items()}|EXTRA|{s.TOKEN_SLOT:'STATUS_SENTINEL'}
        log=(self.root/'helper.log').open('wb');self.files.append(log)
        proc=subprocess.Popen(['/usr/bin/timeout','--signal=KILL','120s','/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py','serve-setup'],cwd=self.temp,env=env,stdin=self.null,stdout=log,stderr=log,close_fds=True)
        self.procs.append(proc);self.assertEqual(proc.wait(timeout=10),1)
        raw=(self.root/'helper.log').read_bytes()
        self.assertIn(b'"kind": "BLOCKED"',raw);self.assertIn(b'ValueError',raw)
        self.assertNotIn(b'"kind": "CUSTODY"',raw);self.assertFalse((self.root/'started.json').exists())
        self.assertNotIn(b'STATUS_SENTINEL',raw)

    def test_wrong_App_blocks_before_launch_exec(self):
        self.wrappers();self.assertFalse(self.start({'PROOF6_APP_TOKEN':'APP_SENTINEL'}))
        rc,raw=self.reap();self.assertNotEqual(rc,0);self.assertIn(b'LAUNCH_ENVIRONMENT',raw)
        self.assertNotIn(b'LAUNCH_EXEC',raw);self.assertNotIn(b'APP_SENTINEL',raw)

    def test_actual_writer_launch_exec_identity_and_custody(self):
        self.wrappers()
        # Only the actual writer's custody boundary is exercised; no runtime main.
        (self.scripts/'actions_runtime.py').write_text(prior.n.LOAD+"\ns.custody(False)\ns.receipt('INERT_WRITER_CUSTODY',pid=os.getpid(),acceptance_credit=False)\n")
        proc=subprocess.Popen(['/usr/bin/timeout','--signal=KILL','120s','/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py','launch-writer'],
            cwd=self.temp,env=self.env|EXTRA|{'PROOF6_APP_TOKEN':'APP_SENTINEL'},stdin=self.null,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
        self.procs.append(proc);out,err=proc.communicate(timeout=10)
        self.assertEqual(proc.returncode,0,(out+err).decode())
        self.assertIn(b'INERT_WRITER_CUSTODY',out)
        for value in (b'APP_SENTINEL',b'STATUS_SENTINEL',b'UNRELATED_',b'DEBIAN_FRONTEND'):self.assertNotIn(value,out+err)

    def test_peer_status_delivery_blocks_and_helper_reaped(self):
        self.wrappers();self.assertTrue(self.start())
        rc,out=self.producer({s.TOKEN_SLOT:'STATUS_SENTINEL'});self.assertNotEqual(rc,0)
        self.assertIn(b'LAUNCH_ENVIRONMENT',out);self.assertNotIn(b'STATUS_SENTINEL',out)
        self.assertNotEqual(self.reap(terminate=True)[0],0)

    def test_permission_failure_still_blocks_after_launch(self):
        self.wrappers(permissions=dict(s.PERMISSIONS,Contents='read'));self.assertFalse(self.start())
        rc,raw=self.reap();self.assertNotEqual(rc,0);self.assertIn(b'EFFECTIVE_PERMISSIONS',raw)

    def test_unknown_runner_still_blocks_after_launch(self):
        self.wrappers(version='0.0.0');self.assertFalse(self.start())
        rc,raw=self.reap();self.assertNotEqual(rc,0);self.assertIn(b'RUNNER_HEADER',raw)

    def test_socket_failure_retains_stage_errno_and_reaps(self):
        self.wrappers();(self.root/'events.sock').write_bytes(b'occupied')
        self.assertFalse(self.start());rc,raw=self.reap();self.assertNotEqual(rc,0)
        self.assertIn(b'"stage": "SOCKET_BIND"',raw);self.assertIn(b'"errno": 98',raw)
        self.assertIn(b'EADDRINUSE',raw)

    def test_nonzero_cleanup_output_survives_shell_capture(self):
        self.wrappers(permissions=dict(s.PERMISSIONS,Contents='read'));self.assertFalse(self.start());self.reap()
        command='set +e\nresult=$(/usr/bin/python3 -I -B proofs/proof6/d04_signal.py cleanup-setup)\ncode=$?\nprintf "%s\\n" "$result"\nexit "$code"\n'
        result=subprocess.run(['/bin/bash','-c',command],cwd=self.temp,env=self.env,capture_output=True,timeout=12)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'HELPER_REAPED',result.stdout);self.assertIn(b'EFFECTIVE_PERMISSIONS',result.stdout)


if __name__=='__main__':
    print(json.dumps(dict(kernel=os.uname().release,acceptance_credit=False,provider_writes=0)),flush=True)
    unittest.main(verbosity=2)
