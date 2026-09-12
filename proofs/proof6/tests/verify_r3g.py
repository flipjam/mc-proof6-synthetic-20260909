"""Offline source inventory, canonical 72-row mapping and workflow checks.

Requires PyYAML for parsing only. Invokes git show and bash -n, never GitHub.
"""
import collections
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import yaml

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT/'proofs/proof6/tests/r3g-evidence'


def verify():
    inventory = json.loads(subprocess.check_output([sys.executable,'-B',str(Path(__file__).with_name('verify_candidate.py'))]))
    plan = json.loads((ROOT/'proofs/proof6/proof_plan.json').read_bytes())
    matrix = {}
    for line in (EVIDENCE/'authority-matrix.md').read_text(encoding='utf-8').splitlines():
        if re.match(r'^\| [A-H][0-9]{2} \|',line):
            row = [cell.strip() for cell in line.split('|')[1:-1]]
            assert len(row)==4 and row[0] not in matrix
            matrix[row[0]] = row
    assert len(matrix)==72 and set(matrix)=={r['id'] for r in plan['cases']}
    for row in plan['cases']:
        assert row['required_action']==matrix[row['id']][1]
        assert row['required_result']==matrix[row['id']][2]
        assert row['disposition']=='FRESH' and row['evidence_groups']
    workflow = yaml.load((ROOT/'.github/workflows/proof6-writer.yml').read_bytes(), Loader=yaml.BaseLoader)
    assert set(workflow['on'])=={'workflow_dispatch'}
    assert set(workflow['on']['workflow_dispatch']['inputs'])=={'proposal','proof_operation'}
    assert workflow['concurrency']=={'group':'proof6-authority-writer-r3','cancel-in-progress':'false'}
    assert workflow['permissions']=={'contents':'read','actions':'read'}
    assert set(workflow['jobs'])=={'writer'}
    job=workflow['jobs']['writer']
    assert job['permissions']==workflow['permissions']
    assert job['environment']=='proof6-writer' and job['runs-on']=='ubuntu-24.04'
    steps=job['steps'];ids=[step.get('id') for step in steps]
    assert ids.index('d04-setup') < ids.index('app-token') < ids.index('execute')
    uses=[step['uses'] for step in steps if 'uses' in step]
    assert uses==['actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1']
    assert len(list((ROOT/'.github/workflows').iterdir()))==1
    commands=0
    for step in steps:
        if 'run' in step:
            result=subprocess.run(['wsl','-d','Ubuntu-22.04','--','bash','-n'],input=step['run'].encode(),capture_output=True,timeout=15)
            assert result.returncode==0, result.stderr
            commands+=1
    assert collections.Counter(v['kind'] for v in plan['workflow_runs'].values())=={
        'setup_bootstrap':1,'fault':4,'ordinary':3,'recovery':2}
    assert set(plan['workflow_runs'])=={'S1','F4','F2','F3','R3','O1','O2','F7','R7','O3'}
    assert plan['order']==['S1','freeze','F4','F2','F3','R3','O1/O2','F7','supporting_evidence_deletion','R7','O3','independent_final_review']
    inventory.update(canonical_mandatory_rows_matched=72, workflow_yaml_and_bash_syntax='PASS',
        bash_blocks_checked=commands, one_fixed_workflow=True,
        diagnostic_is_design_provenance_only=True,
        matrix_sha256=hashlib.sha256((EVIDENCE/'authority-matrix.md').read_bytes()).hexdigest())
    return inventory


if __name__=='__main__':
    print(json.dumps(verify(),sort_keys=True,indent=2))
