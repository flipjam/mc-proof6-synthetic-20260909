"""Inert legacy Git/HTTP fixture; original test assertions remain on disk."""
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'proofs/proof6'))
legacy = types.ModuleType('legacy')
raw = Path(__file__).with_name('legacy_r3e.py').read_text()
# Identity-only substitution of fixture inputs; no production monkeypatch.
raw = raw.replace('proof6-operation-journal-r3e', 'proof6-operation-journal-r3g')
raw = raw.replace('proof6-writer-runtime-r3e', 'proof6-writer-runtime-r3g')
raw = raw.replace("'r3e'", "'r3g'")
raw = raw.replace('34b940e0537f57e5fa225768a55214bd3d3c5340',
                  '2f93acf267b99207c7f8220cb6246787a98806ec')
# Fixed clock fixture only: original assertions are unchanged.
raw = raw.replace('side_effect=[0,115,116]', 'side_effect=[0,0,30,30]')
raw = raw.replace("subprocess.check_output(['git', '-C', str(ROOT), 'show', w.BASELINE + ':history.json'])",
                  "(ROOT / 'proofs/proof6/tests/baseline-history.json').read_bytes()")
sys.argv.insert(1, str(ROOT))
exec(compile(raw, 'legacy_r3e.py (identity adapter)', 'exec'), legacy.__dict__)

# Supply the new prior-step setup qualification as an inert fixture. Original
# bootstrap assertions remain verbatim; missing/failed prerequisite is tested
# separately against the production validator and workflow dependency.
from d04_fixtures import prerequisite
_bootstrap_context = legacy.Bootstrap.context
def _qualified_setup_context(test):
    result = _bootstrap_context(test)
    result['PROOF6_D04_SETUP_QUALIFICATION'] = legacy.json.dumps(prerequisite())
    return result
legacy.Bootstrap.context = _qualified_setup_context


def begin_valid(test, op='', n=50):
    """Replace old fake candidate objects with real accepted gate candidates."""
    e = legacy
    obj = e.writer(test.g, n, op)
    journal = e.j.Journal(obj)
    payload = e.w._canonical(e.PLAN['faults'][op]['proposal']) if op else test.proposal
    binding = journal.operation_binding(payload, op)
    if op:
        journal.consume(binding)
    old = test.g.refs[e.w.REF]
    history = test.g.row(old)
    decision = obj._gate.decide(history, e.json.loads(payload))
    assert decision['decision'] == 'ALLOW'
    candidate = {'version': 1, 'events': history['events'] + [decision['candidate_event']]}
    tree = test.g.tree(test.g.blob(e.w._canonical(candidate)), 'history.json')
    child = test.g.commit(tree, [old], str(n))
    return journal, journal.begin(binding, old, child, decision), child


legacy.Candidate.begin = begin_valid

# The successor always reads current authority, even for an empty journal.
# Supply the previously unnecessary inert GET in this retained launcher test.
_outage_main_test = legacy.Candidate.test_d04_main_consumes_then_isolates_actual_runtime
def _outage_main_with_get(test):
    with legacy.patch.object(legacy.ar, 'get', side_effect=lambda path:
                             test.g.api('offline-token', 'GET', '/' + path)):
        _outage_main_test(test)
legacy.Candidate.test_d04_main_consumes_then_isolates_actual_runtime = _outage_main_with_get


def suite():
    e = legacy
    result = e.unittest.TestSuite()
    for cls in (e.Candidate, e.Corrections, e.Bootstrap, e.R3e, e.Framing):
        result.addTests(cls(name) for name in cls.__dict__ if name.startswith('test_'))
    return result


if __name__ == '__main__':
    with legacy.patch.object(legacy.socket, 'socket', side_effect=AssertionError('OFFLINE_ONLY')):
        result = legacy.unittest.TextTestRunner(verbosity=2).run(suite())
    raise SystemExit(not result.wasSuccessful())
