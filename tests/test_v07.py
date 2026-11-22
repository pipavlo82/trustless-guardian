import copy
import importlib.util
import json
from pathlib import Path
import unittest
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('v07_' + name, ROOT/'demo/developer-preview'/f'{name}.py')
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


api = load('agent_tool_v1')


class ProtocolV1(unittest.TestCase):
    def setUp(self):
        self.context = {'policy': {'scope': 'synthetic-file', 'version': 'v1'},
                        'agent_sid': 'test-sid', 'nonce': 'one', 'before_sha256': 'a'*64}
        self.context['policy_sha256'] = api.sha(api.canonical(self.context['policy']))
        self.request, self.envelope = api.propose({'resource': 'synthetic-source', 'content': 'approved:x'}, self.context, 1000)

    def test_exact_translation(self):
        self.assertEqual(self.envelope['request']['schema'], 'guardian.action.v0')
        self.assertEqual(self.envelope['policy_sha256'], self.context['policy_sha256'])
        self.assertNotIn('authorized', self.envelope)

    def test_no_caller_authorization_or_path(self):
        for key in ('authorized', 'path', 'policy', 'server_pid', 'actor'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                api.propose({'resource': 'synthetic-source', 'content': 'x', key: 'caller'}, self.context, 1000)

    def test_context_relations(self):
        for key in ('actor', 'action', 'scope', 'policy_version', 'policy_sha256', 'nonce', 'evidence'):
            value = copy.deepcopy(self.request); value[key] = 'wrong'
            with self.subTest(key=key), self.assertRaises(ValueError):
                api.translate(api.canonical(value), self.context, 1000)

    def test_contract_preimage(self):
        self.context['policy']['scope'] = 'other'
        with self.assertRaises(ValueError): api.translate(api.canonical(self.request), self.context, 1000)

    def test_expiry(self):
        for expiry in (999, 1000, 1046, True, '1045'):
            value = {**self.request, 'expires_at': expiry}
            with self.subTest(expiry=expiry), self.assertRaises(ValueError):
                api.translate(api.canonical(value), self.context, 1000)

    def test_closed_schema_and_payloads(self):
        for raw in (b'{}', b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b' '*16385):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError): api.translate(raw, self.context, 1000)
        for content in ('x'*129, '\u20ac'*43, None):
            with self.subTest(content=content), self.assertRaises(ValueError):
                api.propose({'resource': 'synthetic-source', 'content': content}, self.context, 1000)

    def test_unknown_resource(self):
        with self.assertRaises(ValueError): api.propose({'resource': '../file', 'content': 'x'}, self.context, 1000)

    def test_native_ambiguity_preserved(self):
        native = {'status': 'UNVERIFIABLE', 'decision': 'DENY', 'execution': 'RECOVERY_REQUIRED'}
        result = api.response(self.request, native)
        self.assertEqual(result['native'], native)
        self.assertEqual(result['retry'], 'PROHIBITED')
        self.assertEqual(result['evidence_refs']['tool_request_sha256'], api.sha(api.canonical(self.request)))
        with self.assertRaises(ValueError): api.response(self.request, {'status': 'PASS'})

    def test_population_cannot_silently_infer(self):
        transport = load('run').NoInference()
        self.assertIsNone(transport({'kind': 'ready'}))
        with self.assertRaises(RuntimeError): transport({'kind': 'inference'})

    def test_oracle_does_not_import_enforcement(self):
        import ast
        tree = ast.parse((ROOT/'demo/developer-preview/verify.py').read_text())
        names = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        names += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        self.assertFalse(any(n and n.startswith(('guardian', 'run_agent', 'hermes')) for n in names))


class CapturedOracleV07(unittest.TestCase):
    """Portable consistency controls over captured evidence, not new OS runs."""
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        with zipfile.ZipFile(ROOT/'evidence/v07-development-witness.zip') as archive:
            archive.extractall(cls.temp.name)
        cls.root = Path(cls.temp.name)/'witness'
        cls.oracle = load('verify')

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def report(self, population, edit=None):
        value = json.loads((self.root/population/'observations.json').read_bytes())
        if edit: edit(value)
        return self.oracle.verify(value, self.root/population, self.root/'redaction-manifest.json')

    def test_both_populations_have_positive_control(self):
        for pop in ('live', 'deterministic'):
            with self.subTest(population=pop): self.assertTrue(self.report(pop)['passed'])

    def test_deterministic_never_proves_live_inference(self):
        self.assertEqual(self.report('deterministic')['real_agent_chain'], 'NOT_COVERED')
        self.assertFalse(self.report('deterministic', lambda v: v.update(population='LIVE_MODEL'))['passed'])

    def test_native_bypass_bytes_tamper(self):
        def edit(v): v['controls']['BYPASS']['after']['source']['hex'] = b'bad'.hex()
        self.assertFalse(self.report('deterministic', edit)['passed'])

    def test_v1_response_tamper(self):
        def edit(v): v['controls']['DENY']['tool_observations'][0]['tool_response_v1']['authorization'] = 'ALLOW'
        self.assertFalse(self.report('deterministic', edit)['passed'])

    def test_identity_tamper(self):
        def edit(v): v['controls']['ALLOW']['native']['token']['capability_count'] = 1
        self.assertFalse(self.report('live', edit)['passed'])

    def test_live_mapping_tamper(self):
        def edit(v): v['controls']['ALLOW']['provider_mapping']['model_output']['content'] = 'forged'
        self.assertFalse(self.report('live', edit)['passed'])

    def test_missing_stage(self):
        self.assertFalse(self.report('live', lambda v: v['controls'].pop('RECOVERY'))['passed'])


if __name__ == '__main__': unittest.main()
