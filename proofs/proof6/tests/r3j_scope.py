"""Exact parent scope guard for the specifically approved R3j delta."""
import ast
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
BASE = '27360e3fa227c9665f6447eb254864af08f4b74a'

def identity(raw):
    return raw.replace(b'r3i', b'r3j').replace(b'R3I', b'R3J').replace(b'R3i', b'R3j').replace(
        b'2cb629820e3bd04e7c7edaa2b2364682e4dc5f1b', b'04441e984236d17664c1200868d8cd3ade1dfb81')

def original(path):
    return subprocess.check_output(['git','-C',str(ROOT),'show',BASE+':'+path])

def methods(raw, owner):
    cls = next(n for n in ast.parse(raw).body if isinstance(n, ast.ClassDef) and n.name == owner)
    return {n.name: ast.dump(n) for n in cls.body if isinstance(n, ast.FunctionDef)}

def verify_scope():
    paths = subprocess.check_output(['git','-C',str(ROOT),'ls-tree','-r','--name-only',BASE]).decode().splitlines()
    for path in paths:
        old = original(path)
        raw = (ROOT/path).read_bytes()
        if path == 'proofs/proof6/build.json':
            continue
        if path in ('proofs/proof6/journal.py','proofs/proof6/writer.py','proofs/proof6/actions_runtime.py','proofs/proof6/proof_plan.json'):
            continue
        # Historical assertions/evidence are never rewritten for a successor.
        expected = identity(old) if (path.startswith('proofs/proof6/') and path.count('/') == 2 and path.endswith('.py') or path == '.github/workflows/proof6-writer.yml') else old
        assert raw == expected, path
    for name, owner, changed, added in (
        ('journal.py','Journal',{'append','read'},{'_append_once','_confirm_append'}),
        ('writer.py','_Writer',{'_call'},set())):
        old = methods(identity(original('proofs/proof6/'+name)),owner)
        new = methods((ROOT/'proofs/proof6'/name).read_bytes(),owner)
        assert set(new) == set(old) | added, name
        for method in set(old)-changed:
            assert old[method] == new[method], (name,method)
    # Check module-level definitions too, not merely the unchanged methods.
    for name, owner, changed, added in (
        ('journal.py','Journal',{'append','read'},{'_append_once','_confirm_append'}),
        ('writer.py','_Writer',{'_call'},set())):
        oldtree = ast.parse(identity(original('proofs/proof6/'+name)))
        newtree = ast.parse((ROOT/'proofs/proof6'/name).read_bytes())
        oldcls = next(n for n in oldtree.body if isinstance(n,ast.ClassDef) and n.name==owner)
        newcls = next(n for n in newtree.body if isinstance(n,ast.ClassDef) and n.name==owner)
        oldmethods = {n.name:n for n in oldcls.body if isinstance(n,ast.FunctionDef)}
        newcls.body = [oldmethods[n.name] if isinstance(n,ast.FunctionDef) and n.name in changed else n
                       for n in newcls.body if not (isinstance(n,ast.FunctionDef) and n.name in added)]
        if name=='journal.py':
            newtree.body = [n for n in newtree.body if not (
                isinstance(n,ast.Import) and [a.name for a in n.names]==['time'] or
                isinstance(n,ast.ImportFrom) and n.module=='journal_confirmation')]
        assert ast.dump(oldtree)==ast.dump(newtree), (name,'module scope')
    oldplan = json.loads(identity(original('proofs/proof6/proof_plan.json')))
    newplan = json.loads((ROOT/'proofs/proof6/proof_plan.json').read_bytes())
    assert set(newplan) == set(oldplan) | {'journal_confirmation'}
    for key in set(oldplan)-{'source_base'}:
        assert oldplan[key] == newplan[key], key
    assert newplan['source_base'] == {'commit':BASE,'tree':'c33367ed67b488b552c3a7dbd7a664400290f843'}
    # Exact text delta in runtime: one repeated qualification, three receipt
    # attachments and the prospective plan hash. No other runtime movement.
    before = identity(original('proofs/proof6/actions_runtime.py')).decode()
    after = (ROOT/'proofs/proof6/actions_runtime.py').read_text()
    before = before.replace('81926d6ce00e3b36f84404b217b29c22e4224b2f002115382614feb1a42c3617',
                            __import__('hashlib').sha256((ROOT/'proofs/proof6/proof_plan.json').read_bytes()).hexdigest())
    after = after.replace("        context['d04'].update(stage='POSTCONFIRMATION_READINESS', consumed_record=claim)\n        helper.qualify()\n",'')
    after = after.replace("    if getattr(writer, '_journal_confirmation', None) is not None:\n        result['journal_confirmation'] = writer._journal_confirmation\n",'')
    after = after.replace("            if getattr(context['writer'], '_journal_confirmation', None) is not None:\n                result['journal_confirmation'] = context['writer']._journal_confirmation\n",'')
    after = after.replace("        if getattr(writer, '_journal_confirmation', None) is not None:\n            result['journal_confirmation'] = writer._journal_confirmation\n",'')
    assert before == after, 'actions_runtime.py'
    return True
