import unittest,tempfile,sqlite3,time,concurrent.futures
from pathlib import Path
from research.scoped_execution_lab_v3.unified_admission import init,prepare,advance,connect
def identity():
 return {"grant_id":"g","grant_sha256":"h"*64,"binding_sha256":"b"*64,"owner_session":"s","attempt_id":"a","expires_at":int(time.time())+300,"container_name":"lab-c","image":"sha256:"+"1"*64}
class UnifiedTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(ignore_cleanup_errors=True);self.p=Path(self.t.name)/"unified.sqlite";init(self.p)
 def tearDown(self):self.t.cleanup()
 def test_prepare_atomic(self):
  prepare(self.p,identity())
  with connect(self.p) as db:
   self.assertEqual(db.execute("SELECT state FROM unified_admissions").fetchone()[0],"PREPARED")
   self.assertEqual(db.execute("SELECT new_state FROM unified_transitions").fetchone()[0],"PREPARED")
   self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0],"wal")
 def test_transaction_rollback(self):
  with self.assertRaises(sqlite3.IntegrityError):
   with connect(self.p) as db:
    db.execute("BEGIN IMMEDIATE")
    db.execute("INSERT INTO unified_admissions VALUES ('g','h','b','s','a',9999999999,'PREPARED','c',NULL,'image',NULL,NULL,0)")
    db.execute("INSERT INTO unified_transitions VALUES ('missing',1,NULL,'PREPARED')")
  with connect(self.p) as db:self.assertEqual(db.execute("SELECT COUNT(*) FROM unified_admissions").fetchone()[0],0)
 def test_replay(self):
  prepare(self.p,identity())
  with self.assertRaises(sqlite3.IntegrityError):prepare(self.p,identity())
 def test_full_cas(self):
  prepare(self.p,identity())
  for args in [("PREPARED","DISPATCH_RECORDED",{"container_id":"c"*64}),("DISPATCH_RECORDED","RESULT_OBSERVED",{"outcome":"o"*64}),("RESULT_OBSERVED","RECEIPT_PUBLISHED",{"outcome":"o"*64,"receipt":"r"*64}),("RECEIPT_PUBLISHED","COMMITTED",{"outcome":"o"*64,"receipt":"r"*64})]:
   advance(self.p,"g",args[0],args[1],**args[2])
  with connect(self.p) as db:
   self.assertEqual(db.execute("SELECT state FROM unified_admissions").fetchone()[0],"COMMITTED")
   self.assertEqual(db.execute("SELECT COUNT(*) FROM unified_transitions").fetchone()[0],5)
 def test_wrong_transition(self):
  prepare(self.p,identity())
  with self.assertRaises(ValueError):advance(self.p,"g","PREPARED","COMMITTED",outcome="o"*64,receipt="r"*64)
if __name__=="__main__":unittest.main(verbosity=2)
