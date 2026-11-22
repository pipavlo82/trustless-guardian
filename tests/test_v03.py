"""Portable recovery and mutation-classification checks; no OS claims from mocks."""
from pathlib import Path
import tempfile
import unittest
from guardian.recovery import Journal,provision
from guardian.policy import digest


class Recovery03(unittest.TestCase):
    def test_same_bytes_remain_ambiguous(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'journal';provision(p);j=Journal(p)
            try:
                j.prepare('same',{'before_sha256':digest(b'x'),'after_sha256':digest(b'x'),'resource_identity':[1,2,3],'policy_sha256':'p'})
                self.assertEqual(j.recover(b'x',[1,2,3],'p')[0]['state'],'RECOVERY_REQUIRED')
                self.assertEqual(j.rows()[0]['nonce'],'same')
            finally:j.close()
    def test_invalid_schema_does_not_hold_database(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'journal';db=sqlite3.connect(p)
            with db:db.execute('PRAGMA user_version=2')
            db.close()
            with self.assertRaises(sqlite3.Error):Journal(p)
            p.unlink();self.assertFalse(p.exists())
