"""Retained local reviewer assertions; five explicit R3f confirmation replacements.
The only real sockets are fixed socketpair fixtures. No GitHub transport occurs.
"""
import copy
import io
from pathlib import Path
import socket
import types
import unittest
from unittest.mock import Mock, patch
from support import legacy as t

module = types.ModuleType('retained_reviewer')
module.__dict__.update(contextlib=t.contextlib, copy=copy, io=io, json=t.json,
                       socket=socket, unittest=unittest, Mock=Mock, patch=patch, t=t)
raw = Path(__file__).with_name('legacy_reviewer_r3e.py').read_text()
# Replace only the original temporary-directory import setup. Test assertions
# below BODY remain verbatim. The exact original is retained next to this file.
exec(compile(raw[raw.index('BODY='):], 'legacy_reviewer_r3e.py (fixture adapter)', 'exec'), module.__dict__)

SUPERSEDED = ('test_01_valid_exact','test_09_exact_limit','test_20_qualifying_socket_eof',
              'test_22_missing_completion','test_23_contradictory_completion')


class R3fConfirmation(module.Review):
    def valid(self, body=module.BODY, **kwargs):
        obj, result = self.run_response(self.response(module.cl(len(body)), body, **kwargs))
        self.assertEqual(result['result'], 'INDETERMINATE')
        self.assertEqual(self.h.g.authority_sends, 1)
        response = self.h.g.row(self.h.g.refs[t.j.REF])['d03']['response']
        self.assertEqual(response['declared_body_length'], len(body))
        self.assertEqual(response['consumed_body_length'], len(body))
        self.assertIs(response['connection_eof'], True)
        self.assertIs(response['response_complete'], True)
        before = self.h.g.journal_sends
        t.j.Journal(t.writer(self.h.g, 1)).recover(lambda:t.w.BASELINE)
        self.assertEqual(before, self.h.g.journal_sends)
        # Original finish did not return, so refresh its validated snapshot for
        # the unchanged malformed protected-record challenges in tests 22/23.
        obj._journal.read()
        self.assertEqual(result['result'], 'INDETERMINATE')
        return obj, result


if __name__ == '__main__':
    names = [n for n in module.Review.__dict__ if n.startswith('test_')]
    assert len(names) == 30
    suite = unittest.TestSuite(module.Review(n) for n in names if n not in SUPERSEDED)
    suite.addTests(R3fConfirmation(n) for n in SUPERSEDED)
    print('25 unchanged reviewer tests + 5 explicit R3f confirmation replacements', flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
