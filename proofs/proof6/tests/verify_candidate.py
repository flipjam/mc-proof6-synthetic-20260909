"""Offline byte/inventory/plan verification; no external calls or mutations."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'proofs/proof6'))
import proof_control


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


if __name__ == '__main__':
    plan, plan_sha = proof_control.plan()
    base = plan['source_base']['commit']
    build_path = 'proofs/proof6/build.json'
    build = json.loads((ROOT/build_path).read_bytes())
    production = {p.relative_to(ROOT).as_posix() for p in (ROOT/'proofs/proof6').glob('*.py')}
    tests = {p.relative_to(ROOT).as_posix() for p in (ROOT/'proofs/proof6/tests').glob('*.py')}
    assert production | tests <= set(build)
    assert build_path not in build
    rows = []
    prior = set(subprocess.check_output(['git','-C',str(ROOT),'ls-tree','-r','--name-only',base], text=True).splitlines())
    for name in sorted(set(build) | {build_path} | prior):
        raw = (ROOT/name).read_bytes()
        if name in build: assert digest(raw) == build[name], name
        if name.endswith('.py'): compile(raw, name, 'exec')
        before = subprocess.check_output(['git','-C',str(ROOT),'show',base+':'+name]) if name in prior else None
        rows.append(dict(path=name, change='added' if before is None else 'unchanged' if before==raw else 'modified',
                         before_git_blob=None if before is None else blob(before),
                         before_sha256=None if before is None else digest(before),
                         git_blob=blob(raw), sha256=digest(raw)))
    protected = {'proofs/proof1/replay.py','proofs/proof2/gate.py','proofs/proof6/d03_rejection.py',
                 'proofs/proof6/admission.py','proofs/proof6/reconcile.py','proofs/proof6/diagnostics.py',
                 'proofs/proof6/ruleset_view.py','proofs/proof6/diagnostic-bindings.json'}
    assert all(row['change']=='unchanged' for row in rows if row['path'] in protected)
    ids = [row['id'] for row in plan['cases']]
    assert len(ids) == len(set(ids)) == 72
    print(json.dumps(dict(source_base=base, build_sha256=digest((ROOT/build_path).read_bytes()),
                         proof_plan_sha256=plan_sha, accounting=plan['accounting'],
                         workflow_budget=plan['workflow_budget'], inventory=rows,
                         accepted_mechanisms_byte_identical=True, offline_only=True), indent=2, sort_keys=True))
