"""Portable tests for the exact original Resonance Agent core snapshot, not OS enforcement."""
import hashlib,importlib.util,math,sys,types,unittest
from pathlib import Path
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/"reference_core"/"agent.py"
PIN="6bb44b71c62f54a3e1da2c11c73de5cf33766b8146c9c73f67711b9c07f0f1f6"

def load():
    mod=types.ModuleType("psutil")
    def no_sensors(_):raise RuntimeError("HOST_SENSORS_DISABLED")
    mod.__getattr__=no_sensors
    with patch.dict(sys.modules,{"psutil":mod}):
        spec=importlib.util.spec_from_file_location("_resonance_original_pinned",SOURCE)
        obj=importlib.util.module_from_spec(spec)
        sys.modules[spec.name]=obj
        try:spec.loader.exec_module(obj)
        finally:sys.modules.pop(spec.name,None)
    return obj

class OriginalCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.a=load()
    def signals(self,n):return {k:n for k in self.a.FIELDS}
    def test_snapshot_sha256(self):
        self.assertEqual(hashlib.sha256(SOURCE.read_bytes()).hexdigest(),PIN)
    def test_fields(self):
        self.assertEqual(set(self.a.FIELDS),{"cpu","memory","disk","hour_sin","hour_cos","solar_proxy","lunar_proxy"})
    def test_original_three_steps(self):
        s=self.a.State()
        for n in (.2,.3,.4):s,d=self.a.decide(s,self.signals(n))
        self.assertEqual((s.step,d["action"]),(3,"OBSERVE"))
    def test_original_repeat_determinism(self):
        def run():
            s=self.a.State()
            for n in (.2,.3,.4):s,d=self.a.decide(s,self.signals(n))
            return self.a.asdict(s),d
        self.assertEqual(run(),run())
    def test_extra_field_denied(self):
        x=self.signals(.2);x["extra"]=0
        with self.assertRaises(ValueError):self.a.decide(self.a.State(),x)
    def test_missing_field_denied(self):
        x=self.signals(.2);x.pop("cpu")
        with self.assertRaises(ValueError):self.a.decide(self.a.State(),x)
    def test_nan_denied(self):
        x=self.signals(.2);x["cpu"]=float("nan")
        with self.assertRaises(ValueError):self.a.decide(self.a.State(),x)
    def test_inf_denied(self):
        x=self.signals(.2);x["cpu"]=float("inf")
        with self.assertRaises(ValueError):self.a.decide(self.a.State(),x)
    def test_negative_denied(self):
        x=self.signals(.2);x["cpu"]=-.1
        with self.assertRaises(ValueError):self.a.decide(self.a.State(),x)
    def test_above_one_denied(self):
        x=self.signals(.2);x["cpu"]=1.1
        with self.assertRaises(ValueError):self.a.decide(self.a.State(),x)
    def test_pressure_defer(self):
        s,d=self.a.decide(self.a.State(),self.signals(1))
        self.assertEqual(d["action"],"DEFER")
    def test_sequence(self):
        s=self.a.State()
        for i in range(4):
            s,d=self.a.decide(s,self.signals(.2))
            self.assertEqual(s.step,i+1)
    def test_record_hash_mutation_detected(self):
        s,d=self.a.decide(self.a.State(),self.signals(.2))
        record=self.a.make_record(s,self.signals(.2),d,"2026-11-13T00:00:00Z")
        record["decision"]["action"]="RUN_TOOL"
        recomputed=hashlib.sha256(self.a.canonical({k:v for k,v in record.items() if k!="hash"}).encode()).hexdigest()
        self.assertNotEqual(record["hash"],recomputed)
    def test_sensor_stub_blocks_measure(self):
        with self.assertRaises(RuntimeError):self.a.measure()
    def test_agent_source_not_mutated(self):
        self.assertEqual(hashlib.sha256(SOURCE.read_bytes()).hexdigest(),PIN)

if __name__=="__main__":unittest.main()
