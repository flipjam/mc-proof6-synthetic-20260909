"""Harmless Linux supervisor fixtures. Never execute unshare or a remote request.

The injected child is inert; these tests validate launch mechanics only.
"""
import ctypes
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import d04_fixtures as f


class Native(unittest.TestCase):
    def test_fixed_launcher_scrubs_and_reaps_without_changing_parent(self):
        before = os.readlink('/proc/self/ns/net')
        parent = f.context()
        left, right = socket.socketpair()
        descriptor = fcntl.fcntl(left.fileno(), fcntl.F_DUPFD, 128)
        os.set_inheritable(descriptor, True)
        try:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                child = f.child()
                code = ('import json,os\n'
                        + 'assert "DO_NOT_LEAK" not in repr(dict(os.environ))\n'
                        + 'assert set(os.environ) <= '+repr({'PATH','LANG',*f.cap.RUNNER_KEYS})+'\n'
                        + 'assert os.readlink("/proc/self/ns/net") == '+repr(before)+'\n'
                        + 'try: os.fstat('+str(descriptor)+')\n'
                        + 'except OSError: pass\nelse: raise AssertionError("inherited fd")\n'
                        + 'record=json.loads('+repr(json.dumps(child))+')\n'
                        + 'record["context"]["pid"]=os.getpid()\n'
                        + 'print(json.dumps(record),flush=True)\n')
                (directory/'d04_capability.py').write_text(code)
                left.sendall(b'before'); self.assertEqual(right.recv(6), b'before')
                with patch.object(f.cap, 'context', return_value=parent), \
                     patch.object(f.pre, '__file__', str(directory/'d04_prerequisite.py')), \
                     patch.dict(os.environ, {'GH_TOKEN':'DO_NOT_LEAK','PROOF6_APP_TOKEN':'DO_NOT_LEAK'}):
                    result = f.pre.run()
                self.assertTrue(result['qualified'], result)
                self.assertTrue(result['child_reaped'])
                self.assertFalse(Path('/proc/'+str(result['child']['context']['pid'])).exists())
                self.assertEqual(os.readlink('/proc/self/ns/net'), before)
                left.sendall(b'after'); self.assertEqual(right.recv(5), b'after')
        finally:
            os.close(descriptor); left.close(); right.close()

    def test_inner_native_timeout_kills_and_reaps_nonforking_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            leaf = directory/'d04_capability.py'
            pidfile = directory/'pid'
            leaf.write_text('import os,time\nopen('+repr(str(pidfile))+',"w").write(str(os.getpid()))\ntime.sleep(30)\n')
            actual_popen = subprocess.Popen
            def shortened(command, **kwargs):
                self.assertEqual(command[1:4], ['--foreground','--signal=KILL','20s'])
                command = list(command); command[3] = '0.3s'
                return actual_popen(command, **kwargs)
            with patch.object(f.cap, 'context', return_value=f.context()), \
                 patch.object(f.pre, '__file__', str(directory/'d04_prerequisite.py')), \
                 patch.object(f.pre.subprocess, 'Popen', side_effect=shortened):
                result = f.pre.run()
            self.assertEqual(result['supervisor_exit'], 124)
            self.assertFalse(result['qualified']); self.assertTrue(result['child_reaped'])
            self.assertFalse(Path('/proc/'+pidfile.read_text()).exists())

    def test_outer_group_deadline_covers_worker_inner_supervisor_and_leaf(self):
        # Reap orphaned test descendants in this process, not an unrelated init.
        libc = ctypes.CDLL(None, use_errno=True)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)  # PR_SET_CHILD_SUBREAPER
        try:
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                leaf = directory/'leaf.py'; worker = directory/'worker.py'
                report = directory/'report.json'
                leaf.write_text('import json,os,time\nopen('+repr(str(report))+',"w").write(json.dumps(dict(leaf=os.getpid(),inner=os.getppid(),group=os.getpgrp())))\ntime.sleep(30)\n')
                worker.write_text('import subprocess\nsubprocess.run(["/usr/bin/timeout","--foreground","--signal=KILL","20s","/usr/bin/python3","-I",'+repr(str(leaf))+'])\n')
                with subprocess.Popen(['/usr/bin/timeout','--signal=KILL','1s','/usr/bin/python3','-I',str(worker)],
                                      stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=False) as outer:
                    outer.communicate(timeout=5)
                self.assertEqual(outer.returncode, -9)
                observed = json.loads(report.read_text())
                self.assertEqual(observed['group'], outer.pid)
                deadline = time.monotonic()+3
                while time.monotonic() < deadline:
                    try:
                        pid, _ = os.waitpid(-1, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if not pid:
                        time.sleep(0.01)
                for key in ('leaf','inner'):
                    self.assertFalse(Path('/proc/'+str(observed[key])).exists(), observed)
        finally:
            self.assertEqual(libc.prctl(36, 0, 0, 0, 0), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
