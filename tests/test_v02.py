import json
from pathlib import Path
import tempfile
import unittest
import sqlite3
from guardian.protocol import envelope,LIMIT
from guardian.recovery import Journal,provision
from guardian.policy import canonical,digest


class ProtocolTests(unittest.TestCase):
    def test_exact_envelope(self):
        self.assertEqual(envelope(canonical({'schema':'guardian.ipc.v02','policy_sha256':'pin','request':{'x':1}}),'pin'),{'x':1})
    def test_binding_and_malformed(self):
        for raw in (b'[]',b'{}',b'{"schema":1,"schema":2}',b'{"x":NaN}',b'x'*(LIMIT+1),b'\xff'):
            with self.subTest(raw=raw[:30]),self.assertRaises((ValueError,UnicodeError)):envelope(raw,'pin')
        for change in ({'policy_sha256':'other'},{'schema':'old'},{'authorized':True}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                envelope(canonical({'schema':'guardian.ipc.v02','policy_sha256':'pin','request':{},**change}),'pin')
    def test_missing_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'db'
            with self.assertRaises(OSError):Journal(p)
            self.assertFalse(p.exists())
    def test_recovery_keeps_nonce_tombstones(self):
        for content,identity,expected in ((b'old',[1,2,3],'ABORTED'),(b'new',[1,2,3],'RECOVERY_REQUIRED'),(b'partial',[1,2,3],'RECOVERY_REQUIRED'),(b'old',[9,2,3],'RECOVERY_REQUIRED')):
            with self.subTest(expected=expected),tempfile.TemporaryDirectory() as d:
                p=Path(d)/'db';provision(p);j=Journal(p)
                try:
                    j.prepare('n',{'before_sha256':digest(b'old'),'after_sha256':digest(b'new'),'resource_identity':[1,2,3],'policy_sha256':'pin'})
                    self.assertEqual(j.recover(content,identity,'pin')[0]['state'],expected)
                    self.assertEqual(j.rows()[0]['nonce'],'n')
                finally:j.close()
    def test_commit_stores_receipt_in_same_transaction(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'db';provision(p);j=Journal(p)
            try:
                j.prepare('n',{});j.commit('n',{'receipt':1})
                self.assertEqual(j.rows()[0]['state'],'COMMITTED');self.assertEqual(j.rows()[0]['receipt'],{'receipt':1})
                with self.assertRaises(ValueError):j.commit('n',{})
            finally:j.close()
    def test_unknown_recovery_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'db';provision(p);j=Journal(p)
            try:
                j.prepare('n',{})
                with j.db:j.db.execute("UPDATE operations SET state='UNKNOWN'")
                with self.assertRaises(ValueError):j.rows()
            finally:j.close()
