import unittest,tempfile,sqlite3,concurrent.futures
from pathlib import Path
from research.scoped_execution_lab_v3.lifecycle_db import initialize,transition,status
IDENT={"grant_id":"g","request_sha256":"r"*64,"grant_sha256":"h"*64,"attempt_id":"a","container_id":"c"*64,"image":"sha256:"+"i"*64}
class Tests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(ignore_cleanup_errors=True);self.p=Path(self.t.name)/"lifecycle.sqlite";initialize(self.p)
 def tearDown(self):self.t.cleanup()
 def test_full(self):
  for prev,new in ((None,"PREPARED"),("PREPARED","DISPATCH_RECORDED"),("DISPATCH_RECORDED","RESULT_OBSERVED"),("RESULT_OBSERVED","RECEIPT_PUBLISHED"),("RECEIPT_PUBLISHED","COMMITTED")):
   self.assertEqual(transition(self.p,IDENT,prev,new,outcome="o"*64 if new in ("RESULT_OBSERVED","RECEIPT_PUBLISHED","COMMITTED") else None,receipt="q"*64 if new in ("RECEIPT_PUBLISHED","COMMITTED") else None),new)
  self.assertEqual(status(self.p,"g"),("COMMITTED","o"*64,"q"*64))
  with sqlite3.connect(self.p) as db:
   self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0],"wal")
   self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0],"ok")
   self.assertEqual(db.execute("SELECT COUNT(*) FROM execution_transitions").fetchone()[0],5)
 def test_replay(self):
  transition(self.p,IDENT,None,"PREPARED")
  with self.assertRaises(ValueError):transition(self.p,IDENT,None,"PREPARED")
 def test_wrong_identity(self):
  transition(self.p,IDENT,None,"PREPARED")
  bad=dict(IDENT,container_id="evil")
  with self.assertRaises(ValueError):transition(self.p,bad,"PREPARED","DISPATCH_RECORDED")
 def test_skip(self):
  transition(self.p,IDENT,None,"PREPARED")
  with self.assertRaises(ValueError):transition(self.p,IDENT,"PREPARED","COMMITTED",outcome="o"*64,receipt="q"*64)
 def test_concurrent(self):
  transition(self.p,IDENT,None,"PREPARED")
  def attempt(_):
   try:transition(self.p,IDENT,"PREPARED","DISPATCH_RECORDED");return "PASS"
   except ValueError:return "REFUSED"
  with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:results=list(ex.map(attempt,range(10)))
  self.assertEqual(results.count("PASS"),1);self.assertEqual(results.count("REFUSED"),9)
if __name__=="__main__":unittest.main(verbosity=2)
