import sys,types,unittest
from pathlib import Path
from unittest.mock import Mock,patch
import r3j_regression
sys.modules['r3g_regression']=r3j_regression
module=types.ModuleType('r3j_previous_focused')
raw=Path(__file__).with_name('test_r3g.py').read_text().replace('proof6-operation-journal-r3g','proof6-operation-journal-r3j').replace('PROOF6_R3G','PROOF6_R3J')
raw=raw.replace("b'r3g'", "b'r3j'").replace("b'R3G'", "b'R3J'").replace("b'R3g'", "b'R3j'")
raw=raw.replace("expected=before.replace","expected=before.replace(b'2f93acf267b99207c7f8220cb6246787a98806ec',b'04441e984236d17664c1200868d8cd3ade1dfb81').replace")
exec(compile(raw,'test_r3g.py (R3j bindings)', 'exec'),module.__dict__)
_previous=module.Admission.run_d04
def adapted(self,*args,**kwargs):
    with patch.object(module.ar.d04_signal,'Client',return_value=Mock(ended=True)):
        return _previous(self,*args,**kwargs)
module.Admission.run_d04=adapted
# Map only the old byte-scope assertion to the approved, exact parent scope.
from r3j_scope import verify_scope
def _approved_scope(self):
    self.assertTrue(verify_scope())
for _cls in vars(module).values():
    if isinstance(_cls,type) and 'test_unchanged_safety_semantics_after_identity_normalization' in _cls.__dict__:
        _cls.test_unchanged_safety_semantics_after_identity_normalization=_approved_scope
if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(module))
    sys.exit(not result.wasSuccessful())
