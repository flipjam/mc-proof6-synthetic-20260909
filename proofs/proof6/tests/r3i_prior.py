import sys,types,unittest
from pathlib import Path
from unittest.mock import Mock,patch
import r3i_regression
sys.modules['r3g_regression']=r3i_regression
module=types.ModuleType('r3i_previous_focused')
raw=Path(__file__).with_name('test_r3g.py').read_text().replace('proof6-operation-journal-r3g','proof6-operation-journal-r3i').replace('PROOF6_R3G','PROOF6_R3I')
raw=raw.replace("b'r3g'", "b'r3i'").replace("b'R3G'", "b'R3I'").replace("b'R3g'", "b'R3i'")
raw=raw.replace("expected=before.replace","expected=before.replace(b'2f93acf267b99207c7f8220cb6246787a98806ec',b'2cb629820e3bd04e7c7edaa2b2364682e4dc5f1b').replace")
exec(compile(raw,'test_r3g.py (R3i bindings)', 'exec'),module.__dict__)
_previous=module.Admission.run_d04
def adapted(self,*args,**kwargs):
    with patch.object(module.ar.d04_signal,'Client',return_value=Mock(ended=True)):
        return _previous(self,*args,**kwargs)
module.Admission.run_d04=adapted
if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(module))
    sys.exit(not result.wasSuccessful())
