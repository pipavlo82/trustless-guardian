"""Portable boundary controls; these alone are not OS-enforcement witnesses."""
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from guardian.dispatch import dispatch

class Dispatch04(unittest.TestCase):
    def test_real_write_then_unexpected_exception_is_uncertain(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'resource';p.write_bytes(b'before')
            def execute(*args):p.write_bytes(b'after');raise RuntimeError('after write')
            r=dispatch(SimpleNamespace(execute=execute),b'',None,0)
            self.assertEqual(p.read_bytes(),b'after');self.assertEqual(r['execution'],'RECOVERY_REQUIRED')
            self.assertEqual(r['status'],'UNVERIFIABLE');self.assertFalse(r['retry_permitted'])
    def test_preserves_native_refusal(self):
        result={'status':'REFUTED','decision':'DENY','execution':'NOT_EXECUTED'}
        self.assertIs(dispatch(SimpleNamespace(execute=lambda *a:result),b'',None,0),result)
    def test_termination_not_fabricated_as_response(self):
        def stop(*args):raise SystemExit(73)
        with self.assertRaises(SystemExit):dispatch(SimpleNamespace(execute=stop),b'',None,0)
