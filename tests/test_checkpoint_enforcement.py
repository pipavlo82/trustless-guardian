import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from research.checkpoint_enforcement.gate import protected, recheck_current, CheckpointHold
from research.checkpoint_enforcement import checkpoint_verify


class CheckpointEnforcement(unittest.TestCase):
    def invoke(self, env, root):
        @protected('test', lambda a,k:root)
        def action(): return {'status':'OTHER_AUTHORIZATION_REFUSED'}
        with patch.dict(os.environ, env, clear=True): return action()

    def test_disabled_preserves_other_authorization(self):
        self.assertEqual(self.invoke({},'.')['status'],'OTHER_AUTHORIZATION_REFUSED')

    def test_packaged_mode_cannot_be_disabled_by_environment(self):
        from research.checkpoint_enforcement import gate
        with patch.object(gate,'PACKAGED_REQUIRED',True):
            for value in [None,'0','']:
                env={} if value is None else {'GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED':value}
                self.assertEqual(self.invoke(env,'.')['status'],'HOLD')

    def test_missing_config_holds(self):
        self.assertEqual(self.invoke({'GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED':'1'},'.')['status'],'HOLD')

    def test_invalid_required_mode_holds(self):
        self.assertEqual(self.invoke({'GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED':'0'},'.')['status'],'HOLD')

    def test_recheck_cannot_be_called_without_lease(self):
        with patch.dict(os.environ, {'GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED':'1'}, clear=True):
            with self.assertRaises(CheckpointHold): recheck_current('dispatch')

    def config_case(self, provider='synthetic_challenge', mutate=False, other_root=False):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);p=root/'config.json'
            cfg={'schema':'guardian.external-checkpoint-config.v1','state_root':str(root),'lock_path':str(root/'lock'),'provider':provider,'trust_policy':str(root/'absent'),'trust_policy_sha256':'0'*64,'chain_path':str(root/'chain')}
            raw=json.dumps(cfg).encode();p.write_bytes(raw)
            env={'GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED':'1','GUARDIAN_CHECKPOINT_CONFIG':str(p),'GUARDIAN_CHECKPOINT_CONFIG_SHA256':hashlib.sha256(raw).hexdigest()}
            if mutate:p.write_text('{}')
            return self.invoke(env, root/'other' if other_root else root)

    def test_config_pin(self): self.assertIn('CONFIG_PIN',self.config_case(mutate=True)['reason'])
    def test_state_root_pin(self): self.assertIn('STATE_ROOT',self.config_case(other_root=True)['reason'])
    def test_synthetic_is_not_production_current(self): self.assertIn('LATEST_HEAD_NOT_ESTABLISHED',self.config_case()['reason'])
    def test_finalized_word_is_not_proof(self): self.assertIn('FINALIZED_PROVIDER_NOT_IMPLEMENTED',self.config_case('base_finalized')['reason'])

    def test_direct_native_dispatch_is_gated(self):
        from types import SimpleNamespace
        from research.scoped_execution_lab_v3 import lab
        with patch.dict(os.environ,{'GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED':'1'},clear=True):
            result=lab.execute(None,None,None,None,SimpleNamespace(path=Path('missing/state.sqlite')),None,None,None,Path('must-not-create'))
        self.assertEqual(result['checkpoint_gate'],'ENFORCED');self.assertEqual(result['launches'],0)

    def test_direct_reconciler_is_gated(self):
        from research.scoped_execution_lab_v3.reconcile_v3_hardened import reconcile
        with patch.dict(os.environ,{'GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED':'1'},clear=True):result=reconcile('missing')
        self.assertEqual(result['checkpoint_gate'],'ENFORCED')

    def test_recovery_hold_precedes_native_readback(self):
        from research.scoped_execution_lab_v3 import reconcile_v3_hardened as r
        with patch.dict(os.environ,{'GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED':'1'},clear=True), patch.object(r,'verify',side_effect=RuntimeError('READBACK_BEFORE_ADMISSION')) as observed:
            result=r.reconcile('missing')
        self.assertEqual(result['status'],'HOLD')
        self.assertFalse(observed.called)

    def test_sqlite_connection_closed_on_negative_witness(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);job=root/'job';job.mkdir();scratch=root/'scratch'
            for n in ['request.json','grant.json','receipt.json','dispatch.json','outcome.json','stdout.bin','stderr.bin','worker-witness.json','expectations.json']:(job/n).write_bytes(b'{}')
            (root/'policy.json').write_bytes(b'{}')
            db=sqlite3.connect(root/'state.sqlite');db.execute('pragma journal_mode=wal')
            db.execute('create table unified_admissions(grant_id text)');db.execute('create table unified_transitions(grant_id text, ordinal integer)');db.commit();db.close()
            try:checkpoint_verify.state(root,{},scratch)
            except ValueError as error:
                self.assertIn('HISTORY_COUNT',str(error))
                # Exception traceback is still alive here. A transaction context alone
                # leaves c open on Windows and this unlink is the regression witness.
                (scratch/'state.sqlite').unlink()
            else:self.fail('negative witness was not rejected')
