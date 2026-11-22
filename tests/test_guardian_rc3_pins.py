"""Source pins for research RC3 must match exact published bytes."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]

class CandidatePins(unittest.TestCase):
    def test_exact_published_sources(self):
        p=ROOT/"research"/"scoped_execution_lab_v3"/"RESEARCH_PINS.json"
        info=json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(info["production"],"HOLD")
        self.assertEqual(info["frozen_core_v23_source_sha256"],
            "10790b3fb770496e8213986a320b825fd90dbc9990c96df81fa809fdd5ff257f")
        for name,expected in info["source_sha256"].items():
            item=(ROOT/name).resolve()
            self.assertTrue(item.is_relative_to(ROOT.resolve()))
            self.assertEqual(hashlib.sha256(item.read_bytes()).hexdigest(),expected,name)
        lab=ROOT/"research"/"scoped_execution_lab_v3"
        self.assertEqual(hashlib.sha256((lab/"worker").read_bytes()).hexdigest(),
            info["worker_binary_sha256"])
        self.assertEqual(hashlib.sha256((lab/"image.json").read_bytes()).hexdigest(),
            info["image_pin_sha256"])

if __name__=="__main__":unittest.main()
