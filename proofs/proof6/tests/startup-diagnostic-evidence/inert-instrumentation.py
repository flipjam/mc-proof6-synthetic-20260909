import json,os,sys,socket,subprocess
from pathlib import Path
repo=Path('/mnt/d/Projects/mc-proof6-r3h-s1-startup-diagnostic');os.chdir(repo)
sys.path.insert(0,str(repo/'proofs/proof6'));import d04_signal as s
b=dict(run_id=34723570002,attempt=1,runtime_sha='d4d0d448026b9f0dd0728a852d757543b550208e',target_sha='d4d0d448026b9f0dd0728a852d757543b550208e',context='proof6/d04-signal/34723570002/1/d4d0d448026b9f0dd0728a852d757543b550208e')
root=s.directory(b);assert not root.exists();root.mkdir(mode=0o700)
path=str(root/'events.sock')
with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as server:
 server.bind(path);server.listen(1)
Path(path).unlink()
env=dict(GITHUB_REPOSITORY=s.REPO,GITHUB_REPOSITORY_ID='1363510385',GITHUB_REF=s.RUNTIME,GITHUB_WORKFLOW_REF=s.REPO+'/.github/workflows/proof6-writer.yml@'+s.RUNTIME,GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID=str(b['run_id']),GITHUB_SHA=b['runtime_sha'],PATH='/usr/bin:/bin',LANG='C.UTF-8')
with open('/dev/null','rb') as null,open(root/'helper.log','wb') as log:
 p=subprocess.Popen(['/usr/bin/timeout','--signal=KILL','120s','/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py','serve-setup'],cwd=repo,env=dict(env,PROOF6_D04_STATUS_TOKEN='SYNTHETIC_NONSECRET'),stdin=null,stdout=log,stderr=log,close_fds=True)
 (root/'native.pid').write_text(str(p.pid));rc=p.wait(timeout=10)
(root/'reaped.exit').write_text(str(rc))
log=(root/'helper.log').read_bytes();assert b'UNHANDLED_FAILURE' in log and b'SOURCE_L' in log;assert b'SYNTHETIC_NONSECRET' not in log
assert rc==1 and b'"kind": "CUSTODY"' in log and b'"kind": "BLOCKED"' in log
assert not (root/'started.json').exists()
command='set -euo pipefail\nresult=$(/usr/bin/python3 -I -B proofs/proof6/d04_signal.py cleanup-setup)\nprintf "%s\\n" "$result"\n'
r=subprocess.run(['/bin/bash','-c',command],cwd=repo,env=env,capture_output=True,timeout=10)
assert r.returncode==1 and r.stdout==b'' and r.stderr==b''
direct=subprocess.run(['/usr/bin/python3','-I','-B','proofs/proof6/d04_signal.py','cleanup-setup'],cwd=repo,env=env,capture_output=True,timeout=10)
assert direct.returncode==1 and b'HELPER_REAPED' in direct.stdout and b'BLOCKED' in direct.stdout
result=dict(source='d4d0d448026b9f0dd0728a852d757543b550208e',kernel=os.uname().release,python=sys.version.split()[0],socket_path=path,socket_path_bytes=len(path.encode()),real_bind_listen='PASS',exact_helper_entry_exit=rc,local_custody='PASS',local_worker_ancestor='ABSENT; local expected failure, not attributed to hosted run',startup_marker=False,cleanup_direct_structured_output=True,cleanup_workflow_equivalent_exit=r.returncode,cleanup_workflow_equivalent_stdout_bytes=len(r.stdout),cleanup_suppression='REPRODUCED',acceptance_credit=False,provider_writes=0)
print(json.dumps(result,sort_keys=True,indent=2));print(log.decode())
