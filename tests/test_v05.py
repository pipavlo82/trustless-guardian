"""Portable evidence-oracle checks, NOT Windows enforcement or AI-agent tests."""
import ast
import copy
import json
from pathlib import Path
import unittest

from demo.verify_demo import verify
from demo.tool_adapter import proposal
from tools.v05_mutations import classify

ROOT = Path(__file__).resolve().parents[1]


class V05(unittest.TestCase):
    def setUp(self):
        self.value = json.loads((ROOT/'demo/captured_laboratory_vector.json').read_bytes())

    def test_captured_laboratory_record(self):
        result = verify(self.value)
        self.assertTrue(result['laboratory_passed'])
        self.assertEqual(result['real_agent_status'], 'NOT_COVERED')

    def test_evidence_corruption(self):
        for scenario in self.value['controls']:
            with self.subTest(scenario=scenario):
                v = copy.deepcopy(self.value); v['controls'][scenario]['after']['source']['sha256'] = '0'*64
                self.assertFalse(verify(v)['laboratory_passed'])

    def test_claim_promotion(self):
        v = copy.deepcopy(self.value); v['real_agent_status'] = 'VERIFIED'
        self.assertFalse(verify(v)['laboratory_passed'])
        v = copy.deepcopy(self.value); v['controls']['RECOVERY']['response']['execution'] = 'NOT_EXECUTED'
        self.assertFalse(verify(v)['laboratory_passed'])

    def test_contract_preimage(self):
        v = copy.deepcopy(self.value); v['policy']['max_bytes'] += 1
        self.assertFalse(verify(v)['laboratory_passed'])

    def test_oracle_import_boundary(self):
        tree = ast.parse((ROOT/'demo/verify_demo.py').read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertFalse(any(x.name.startswith('guardian') for x in node.names))
            if isinstance(node, ast.ImportFrom):
                self.assertFalse((node.module or '').startswith('guardian'))

    def test_proposal_has_no_authority(self):
        p = self.value['policy']; v = {'resource': p['resource'], 'content': 'approved:x', 'nonce': 'x', 'expires_at': 1030, 'before_sha256': '0'*64}
        context = {'actor': 'fixture-actor', 'policy': p, 'policy_sha256': '0'*64}
        result = json.loads(proposal(v, **context))
        self.assertNotIn('authorized', result)
        for patch in ({'authorized': True}, {'actor': 'forged'}, {'resource': 'elsewhere'}):
            with self.assertRaises(ValueError): proposal({**v, **patch}, **context)

    def test_mutation_crash_not_kill(self):
        ok = {'laboratory_passed': True}
        self.assertEqual(classify(ok, None, ok, 'deny', True, True), 'CRASHED')
        self.assertEqual(classify(None, None, ok, 'deny', True, True), 'CONTROL_BROKEN')
        self.assertEqual(classify(ok, None, ok, 'deny', True, False), 'NOT_APPLIED')

    def test_transport_failure_not_semantic_kill(self):
        ok = {'laboratory_passed': True}
        checks = {k: True for k in ('allow_bytes', 'allow_outcome', 'allow_request', 'allow_ipc_identity', 'receipt_bindings', 'receipt_digest', 'bypass_positive')}
        changed = {'checks': {**checks, 'deny': False}, 'target_observation': {'response': {'status': 'UNVERIFIABLE'}}}
        self.assertEqual(classify(ok, changed, ok, 'deny', True, True), 'CONTROL_BROKEN')


if __name__ == '__main__': unittest.main()
