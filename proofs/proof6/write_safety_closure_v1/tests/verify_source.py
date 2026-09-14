"""Read-only source identity, scope, AST reuse, build and inert workflow checks."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
AREA = ROOT/'proofs/proof6/write_safety_closure_v1'
BASE = '118e8bbe2994689e819f7ae217e43df7df3f70b9'
TREE = '478f5a466690cd6c4ab96d94da25ffd052b00603'
EXPECTED = {
    'proofs/proof1/replay.py': ('efdfb8fbcd293e006709ca386d337814ce19683c', 'ac9c761cf57d74ef68f35213de333c2d071c1f030ad592cae444c3bee576474e'),
    'proofs/proof2/gate.py': ('1866724af1908053491b945a902a3d0038abca5d', 'e432172177d7d58d1b9424c4547f31e7223295eeb80d0a3235bd2e7092ca60bf'),
    'proofs/proof6/d03_rejection.py': ('1ac498b5c67d7f6690f2bdbf421af954daa07db9', '79af705e8b0f405d4ceda4bd12b4550dea9d0cb2cb2330252baf6e40c1132db1'),
    'proofs/proof6/sibling_canary.py': ('e96d42a1c5ebcb0680b05ad128d274ee313d136d', '33fb1c915f134f57055ea22702dbe91a481fd1b6a313f1221ddd3346bdf94e86'),
    'proofs/proof6/journal_confirmation.py': ('395d24587d93554aba47e878b697a47afd518c2b', 'b8b34d4335047841eac2062f77867d8d90f53de0411674d564f81ec4fecf7465'),
}


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def functions(raw):
    tree = ast.parse(raw)
    result = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            result[node.name] = ast.dump(node, include_attributes=False)
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, ast.FunctionDef):
                    result[node.name+'.'+child.name] = ast.dump(child, include_attributes=False)
    return result


def main():
    assert git('remote', 'get-url', 'origin').decode().strip() == 'https://github.com/flipjam/mc-proof6-synthetic-20260909.git'
    assert git('rev-parse', BASE+'^{tree}').decode().strip() == TREE
    identities = {}
    for path, (blob, digest) in EXPECTED.items():
        raw = git('show', BASE+':'+path)
        assert git('rev-parse', BASE+':'+path).decode().strip() == blob
        assert hashlib.sha256(raw).hexdigest() == digest
        assert git('diff', BASE, '--', path) == b''
        identities[path] = dict(blob=blob, sha256=digest, result='MATCH')
    unchanged, changed, removed = {}, {}, {}
    for filename in ('writer.py', 'journal.py', 'proof_control.py', 'd03_job_token.py', 'd03_rejection.py', 'sibling_canary.py', 'journal_confirmation.py'):
        old = functions(git('show', BASE+':proofs/proof6/'+filename))
        new = functions((AREA/filename).read_bytes())
        unchanged[filename] = sorted(k for k in old if old[k] == new.get(k))
        changed[filename] = sorted(k for k in new if old.get(k) != new[k])
        removed[filename] = sorted(set(old)-set(new))
    for function in ('_d03_complete_body', '_Writer._validate_transition', '_Writer.recover_only'):
        assert function in unchanged['writer.py'], function
    for function in ('Journal.read', 'Journal.append', 'Journal._confirm_append', 'Journal.arm', 'Journal.take_send', 'Journal.finish', 'Journal.recover'):
        assert function in unchanged['journal.py'], function
    for filename in ('sibling_canary.py', 'journal_confirmation.py'):
        assert (AREA/filename).read_bytes() == git('show', BASE+':proofs/proof6/'+filename)
    assert not changed['d03_rejection.py']
    for function in ('_worker_log', '_permission_evidence', 'validate'):
        assert function in unchanged['d03_job_token.py']
    old_patch = ast.get_source_segment(git('show', BASE+':proofs/proof6/writer.py').decode(), next(
        n for n in ast.walk(ast.parse(git('show', BASE+':proofs/proof6/writer.py'))) if isinstance(n, ast.FunctionDef) and n.name == '_patch'))
    current_patch = next(n for n in ast.walk(ast.parse((AREA/'writer.py').read_bytes())) if isinstance(n, ast.FunctionDef) and n.name == '_patch')
    assert ast.dump(ast.parse(old_patch.replace('heads/proof6-authority', 'heads/proof6-ws-closure-v1-authority')).body[0]) == ast.dump(current_patch)
    # Collector import closure must not reach the mutation modules.
    pure = ('collector.py', 'qualification.py', 'common.py', 'proof_control.py', 'd03_rejection.py', 'd03_job_token.py', 'ruleset_view.py')
    for filename in pure:
        tree = ast.parse((AREA/filename).read_bytes())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module not in ('writer', 'journal', 'sibling_canary')
            if isinstance(node, ast.Import):
                assert not any(n.name in ('writer', 'journal', 'sibling_canary') for n in node.names)
    for p in AREA.glob('*.py'):
        ast.parse(p.read_bytes())
        text = p.read_text()
        assert not any(s in text for s in ('D02_PRE_SEND_STOP', 'D04_CONNECTIVITY_OUTAGE', 'range(72)', 'workflow_runs'))
    workflow = (ROOT/'.github/workflows/proof6-write-safety-closure-v1.yml').read_text()
    assert '\n  workflow_dispatch:' in workflow and '\n  push:' not in workflow and '\n  pull_request:' not in workflow
    assert 'group: proof6-ws-closure-v1-writer' in workflow and 'cancel-in-progress: false' in workflow
    assert 'type: choice' in workflow and workflow.count('type: choice') == 1
    assert "github.ref == 'refs/heads/proof6-ws-closure-v1-runtime'" in workflow
    assert 'environment: proof6-ws-closure-v1' in workflow and 'P6WSV1_FROZEN_MANIFEST' in workflow
    build = json.loads((AREA/'build.json').read_bytes())
    expected_files = {p.relative_to(ROOT).as_posix() for p in AREA.glob('*.py')}
    expected_files |= {'proofs/proof1/replay.py', 'proofs/proof2/gate.py', '.github/workflows/proof6-write-safety-closure-v1.yml'}
    assert set(build['sha256']) == expected_files
    for path, digest in build['sha256'].items():
        assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest() == digest
    print(json.dumps(dict(result='PASS', base=BASE, tree=TREE, identities=identities,
        unchanged_functions=unchanged, changed_functions=changed, removed_functions=removed,
        authority_transport='AST_IDENTICAL_EXCEPT_FIXED_REF', all_15_invariants='PRESERVED',
        workflow='MANUAL_ONLY_FROZEN_RUNTIME_AND_ENVIRONMENT_BOUND', collector='NO_MUTATION_IMPORTS',
        build='ALL_RUNTIME_SOURCE_HASHES_MATCH'), indent=2))


if __name__ == '__main__':
    main()
