import json,sqlite3,tempfile,unittest,shutil
from pathlib import Path
from contextlib import closing
from unittest.mock import patch
from research.checkpoint_enforcement import checkpoint_verify as v
from research.scoped_execution_lab_v3.unified_state import UnifiedState

F=Path(__file__).resolve().parents[1]/'research/checkpoint_enforcement/fixtures/bootstrap.json'
class Bootstrap(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'state';self.root.mkdir();(self.root/'intent').mkdir()
        self.f=json.loads(F.read_bytes())
        # Own every connection created by the unchanged native schema initializer.
        # Its transaction context is not a connection-close context on Windows.
        from research.scoped_execution_lab_v3 import unified_admission as u
        original=u.connect;opened=[]
        def tracked(path):
            c=original(path);opened.append(c);return c
        try:
            with patch.object(u,'connect',tracked):UnifiedState(self.root/'state.sqlite','test')
        finally:
            for c in opened:c.close()
        for name in ['request','grant']:(self.root/'intent'/(name+'.json')).write_bytes(v.encode(self.f[name])+b'\n')
        (self.root/'policy.json').write_bytes(v.encode(self.f['policy'])+b'\n')
    def compute(self):return v.bootstrap_state(self.root,self.f['trust'],Path(self.tmp.name)/'read')
    def test_exact_signed_bootstrap_digest(self):
        s=self.compute();self.assertEqual(v.digest(v.encode(s)),self.f['chain'][0]['record']['state_digest'])
        self.assertIsNone(s['admission']);self.assertEqual(s['transitions'],[])
    def test_full_signed_bootstrap_to_committed_chain(self):
        self.assertEqual(v.chain_valid(self.f['chain'],self.f['trust'])['record']['recovery_state'],'COMMITTED')
    def test_missing_intent_is_not_empty_observation(self):
        (self.root/'intent/request.json').unlink()
        with self.assertRaises(FileNotFoundError):self.compute()
    def test_missing_database_cannot_be_created_as_zero(self):
        # Existing connection handles from init are released before physical removal.
        import gc;gc.collect()
        for p in self.root.glob('state.sqlite*'):p.unlink()
        with self.assertRaises(sqlite3.OperationalError):self.compute()
    def test_changed_request_refused(self):
        self.f['request']['request_id']='substituted'
        (self.root/'intent/request.json').write_bytes(v.encode(self.f['request'])+b'\n')
        with self.assertRaises(ValueError):self.compute()
    def test_signature_corruption_refused(self):
        self.f['grant']['signature']='A'*86+'=='
        (self.root/'intent/grant.json').write_bytes(v.encode(self.f['grant'])+b'\n')
        with self.assertRaises(Exception):self.compute()
    def test_missing_table_is_not_zero_admissions(self):
        with closing(sqlite3.connect(self.root/'state.sqlite')) as c:c.execute('drop table unified_transitions');c.commit()
        with self.assertRaises(sqlite3.OperationalError):self.compute()
    def test_wrong_external_request_pin_refused(self):
        self.f['trust']['native_pins']['request_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'REQUEST_PIN'):self.compute()
