import unittest,tempfile,json,hashlib,os
from pathlib import Path
from research.scoped_execution_lab_v3.atomic_receipt import publish
class AtomicReceiptTests(unittest.TestCase):
 @unittest.skipUnless(os.name == 'nt', 'Windows-only atomic receipt writer')
 def test_publish_and_readback(self):
  with tempfile.TemporaryDirectory() as d:
   receipt={"request":"synthetic-1","signature":"TEST_ONLY_NOT_CRYPTOGRAPHIC"}
   canonical=lambda x:json.dumps(x,sort_keys=True,separators=(",",":")).encode()
   try:h=publish(d,receipt,canonical)
   except OSError as e:
    if "DIRECTORY_DURABILITY_UNAVAILABLE" in str(e):self.skipTest("directory durability unavailable")
    raise
   self.assertEqual(h,hashlib.sha256((Path(d)/"receipt.json").read_bytes()).hexdigest())
   with self.assertRaises(ValueError):publish(d,receipt,canonical)
 def test_no_overwrite_existing(self):
  with tempfile.TemporaryDirectory() as d:
   (Path(d)/"receipt.json").write_bytes(b"incumbent")
   with self.assertRaises(ValueError):publish(d,{"x":1},lambda x:b"test")
   self.assertEqual((Path(d)/"receipt.json").read_bytes(),b"incumbent")
if __name__=="__main__":unittest.main()
