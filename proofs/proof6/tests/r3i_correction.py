"""Retain 20 correction tests and five counterexamples with successor schemas."""
import json
from pathlib import Path
import socket
import sys
import types
import unittest
from unittest.mock import patch
import r3i_prior
sys.modules['test_r3g']=r3i_prior.module
import test_r3g_correction

if __name__=='__main__':
    path=Path(__file__).with_name('reproduce_r3g_review.py')
    module=types.ModuleType('r3i_review');module.__file__=str(path)
    source=path.read_text(encoding='utf-8').replace('PROOF6_R3G','PROOF6_R3I')
    with patch.object(socket,'socket',side_effect=AssertionError('OFFLINE_ONLY')):
        exec(compile(source,'reproduce_r3g_review.py (R3i schemas)','exec'),module.__dict__)
        findings=module.reproduce()
        print(json.dumps({'counterexamples':findings,'all_five_rejected':all(findings.values())},sort_keys=True),flush=True)
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(test_r3g_correction))
    sys.exit(not (all(findings.values()) and result.wasSuccessful()))
