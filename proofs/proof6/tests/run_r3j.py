"""Reproduce the complete offline R3j package; no GitHub/provider commands."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[3]
OUT=ROOT/'proofs/proof6/tests/r3j-evidence'
GROUPS=[('retained','r3j_regression.py',198),('prior-focused','r3j_prior.py',68),
 ('correction','r3j_correction.py',20),('focused','test_r3j.py',60),
 ('bounded','test_r3j_bounded.py',20),('startup','test_r3j_startup.py',20),
 ('native-prerequisite','native_prerequisite_fixture.py',3),
 ('native-signal','native_r3j_signal_fixture.py',7),('native-bounded','native_r3j_bounded.py',28),
 ('native-startup','native_r3j_startup.py',9),('custody','test_r3j_custody.py',49),
 ('native-custody','native_r3j_custody.py',46),('confirmation','test_r3j_confirmation.py',138),
 ('lifecycle','test_r3j_lifecycle.py',10),('inventory','verify_r3j.py',0)]

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def run():
    OUT.mkdir(exist_ok=True);final=OUT/'final-tests';final.mkdir(exist_ok=True)
    results=[]
    for label,name,count in GROUPS:
        if sys.platform=='win32' and label.startswith('native'):
            # Local WSL2 native Linux root used for real Unix IPC/process tests.
            linux='/mnt/'+str(ROOT)[0].lower()+str(ROOT)[2:].replace('\\','/')
            cmd=['wsl','-d','docker-desktop','--','chroot','/mnt/host/wsl/mc-p6-r3i-linux',
                 '/usr/bin/python3','-B',linux+'/proofs/proof6/tests/'+name]
        else:cmd=[sys.executable,'-B',str(ROOT/'proofs/proof6/tests'/name)]
        start=time.monotonic();result=subprocess.run(cmd,cwd=ROOT,capture_output=True,timeout=240)
        raw=result.stdout+result.stderr;path=final/(label+'.log');path.write_bytes(raw)
        actual=sum(int(n) for n in re.findall(rb'Ran (\d+) tests? in ',raw))
        assert result.returncode==0 and actual==count,(label,result.returncode,actual,count,str(path))
        results.append(dict(group=label,tests=actual,exit_code=result.returncode,sha256=digest(path),seconds=round(time.monotonic()-start,3)))
        if label=='inventory':(OUT/'source-inventory.json').write_bytes(result.stdout)
        print(label,actual,'PASS',flush=True)
    value=dict(result='PASS',tests=sum(x['tests'] for x in results),groups=results,
        accepted_R3i_baseline_tests=528,source_parent='27360e3fa227c9665f6447eb254864af08f4b74a',
        build_sha256=digest(ROOT/'proofs/proof6/build.json'),plan_sha256=digest(ROOT/'proofs/proof6/proof_plan.json'),
        acceptance_credit=False,hosted_runs=0,mandatory_fresh=72,inherited=0,NOT_APPLICABLE=0)
    (OUT/'test-results.json').write_bytes(json.dumps(value,sort_keys=True,indent=2).encode()+b'\n')
    print('TOTAL',value['tests'],'PASS',flush=True)

if __name__=='__main__':run()
