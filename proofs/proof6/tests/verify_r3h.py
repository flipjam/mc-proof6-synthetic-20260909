"""Read-only full source inventory, exact canonical rows, YAML and Bash checks."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import yaml

ROOT=Path(__file__).resolve().parents[3]
BASE='73b686f16b052695a4c41706b4b777206a6b0ba1'
EVIDENCE=ROOT/'proofs/proof6/tests/r3h-evidence'


def verify():
    result=subprocess.run([sys.executable,'-B',str(ROOT/'proofs/proof6/tests/verify_candidate.py')],
        cwd=ROOT,capture_output=True,timeout=60)
    assert result.returncode==0,result.stderr.decode(errors='replace')
    inventory=json.loads(result.stdout);assert inventory['source_base']==BASE
    plan=json.loads((ROOT/'proofs/proof6/proof_plan.json').read_bytes())
    rows={}
    matrix=(EVIDENCE/'authority-matrix.md').read_bytes()
    assert hashlib.sha1(b'blob '+str(len(matrix)).encode()+b'\0'+matrix).hexdigest()=='373754b4c2721e2d78d6cfa4d48b2aad786bbbe0'
    for line in matrix.decode('utf-8').splitlines():
        parts=[x.strip() for x in line.strip().strip('|').split('|')]
        if len(parts)==4 and re.fullmatch('[A-H][0-9]{2}',parts[0]):rows[parts[0]]=parts
    assert len(rows)==72 and {x['id'] for x in plan['cases']}==set(rows)
    for row in plan['cases']:
        assert [row['required_action'],row['required_result']]==rows[row['id']][1:3]
        assert row['disposition']=='FRESH' and row['evidence_groups']
    identity_only=('writer.py','journal.py','app_probes.py','d03_job_token.py','d04_capability.py','d04_prerequisite.py')
    for name in identity_only:
        old=subprocess.check_output(['git','-C',str(ROOT),'show',BASE+':proofs/proof6/'+name])
        expected=old.replace(b'r3g',b'r3h').replace(b'R3G',b'R3H').replace(b'R3g',b'R3h')
        if name=='writer.py':expected=expected.replace(b'2f93acf267b99207c7f8220cb6246787a98806ec',b'd754156067cf1aa2318e7b04d7fcf47902eb9846')
        assert (ROOT/'proofs/proof6'/name).read_bytes()==expected,name
    for name in ('outage.py','admission.py','reconcile.py','d03_rejection.py','sibling_canary.py'):
        assert (ROOT/'proofs/proof6'/name).read_bytes()==subprocess.check_output(['git','-C',str(ROOT),'show',BASE+':proofs/proof6/'+name]),name
    workflow=yaml.load((ROOT/'.github/workflows/proof6-writer.yml').read_bytes(),Loader=yaml.BaseLoader)
    assert set(workflow['on'])=={'workflow_dispatch'}
    assert set(workflow['jobs'])=={'signal_setup','writer','d04_writer'}
    assert workflow['permissions']==workflow['jobs']['writer']['permissions']=={'contents':'read','actions':'read'}
    assert workflow['jobs']['d04_writer']['permissions']=={'statuses':'write'}
    setup=workflow['jobs']['signal_setup']
    assert setup['permissions']=={'statuses':'write'}
    assert workflow['jobs']['writer']['needs']=='signal_setup'
    assert setup['outputs']=={'qualification':'${{ steps.qualified.outputs.qualification }}'}
    assert all("vars.PROOF6_FROZEN_MANIFEST == ''" in step['if'] for step in setup['steps'])
    assert workflow['concurrency']=={'group':'proof6-authority-writer-r3','cancel-in-progress':'false'}
    normal=workflow['jobs']['writer']['if'].split("result == 'skipped') && ",1)[1];d04=workflow['jobs']['d04_writer']['if']
    assert normal.replace("!= 'D04_CONNECTIVITY_OUTAGE'","== 'D04_CONNECTIVITY_OUTAGE'")==d04
    blocks=0
    for job in workflow['jobs'].values():
        assert job['environment']=='proof6-writer' and job['runs-on']=='ubuntu-24.04'
        for step in job['steps']:
            if 'run' not in step:continue
            command=['wsl','-d','Ubuntu-22.04','--','bash','-n'] if sys.platform=='win32' else ['bash','-n']
            check=subprocess.run(command,input=step['run'].encode(),capture_output=True,timeout=15)
            assert check.returncode==0,check.stderr;blocks+=1
    assert len(list((ROOT/'.github/workflows').iterdir()))==1
    inventory.update(canonical_rows=72,fresh=72,inherited=0,NOT_APPLICABLE=0,
        matrix_git_blob='373754b4c2721e2d78d6cfa4d48b2aad786bbbe0',
        authority_main=plan['contract_commit'],identity_only=list(identity_only),
        bash_blocks_checked=blocks,workflow_permissions='PASS',source_only=True,
        signal_setup_required_before_freeze=True,signal_setup_hosted_execution=False,
        canary_credit=0,R3h_provisioned=False,R3h_frozen=False,R3h_executed=False)
    return inventory


if __name__=='__main__':
    print(json.dumps(verify(),sort_keys=True,indent=2))
