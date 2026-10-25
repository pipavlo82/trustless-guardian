import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT/'demo/real-agent'
spec = importlib.util.spec_from_file_location('guardian_v06_protocol', DIRECTORY/'protocol.py')
protocol = importlib.util.module_from_spec(spec); spec.loader.exec_module(protocol)
spec = importlib.util.spec_from_file_location('guardian_v06_mutations', DIRECTORY/'mutation_spec.py')
mutations = importlib.util.module_from_spec(spec); spec.loader.exec_module(mutations)
spec = importlib.util.spec_from_file_location('guardian_v06_oracle', DIRECTORY/'verify.py')
oracle = importlib.util.module_from_spec(spec); spec.loader.exec_module(oracle)


class V06(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        with zipfile.ZipFile(ROOT/'evidence/v06-real-agent-witness.zip') as z:
            if any(Path(n).is_absolute() or '..' in Path(n).parts for n in z.namelist()):
                raise ValueError('UNSAFE_ARCHIVE')
            z.extractall(cls.temp.name)
        cls.public = Path(cls.temp.name)/'public'
        cls.observed = json.loads((cls.public/'normal/observations.json').read_bytes())

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def check_record(self, value):
        return oracle.verify(value,self.public/'normal',self.public/'redaction-manifest.json')

    def test_captured_real_agent_record(self):
        self.assertTrue(self.check_record(self.observed)['passed'])

    def test_forged_confinement_rejected(self):
        v=copy.deepcopy(self.observed);v['controls']['ALLOW']['native']['token']['appcontainer']=False
        self.assertFalse(self.check_record(v)['checks']['ALLOW_native_token'])

    def test_forged_model_selection_rejected(self):
        v=copy.deepcopy(self.observed);v['controls']['DENY']['provider_mapping']['model_output']['resource']='synthetic-source'
        self.assertFalse(self.check_record(v)['checks']['DENY_provider_record'])

    def test_postwrite_not_executed_promotion_rejected(self):
        v=copy.deepcopy(self.observed);v['controls']['RECOVERY']['tool_observations'][0]['result']['execution']='NOT_EXECUTED'
        self.assertFalse(self.check_record(v)['checks']['recovery'])

    def test_strict_proposal(self):
        value = {'tool':'guardian_action','resource':'synthetic-source','content':'approved:x'}
        self.assertEqual(protocol.proposal(value), value)
        for patch in ({'authorized':True}, {'path':'C:/private'}, {'actor':'claimed'}):
            with self.assertRaises(ValueError): protocol.proposal({**value, **patch})

    def test_unknown_tool_and_resource(self):
        for key, value in [('tool','shell'), ('resource','arbitrary'), ('content','x'*129)]:
            x = {'tool':'guardian_action','resource':'synthetic-source','content':'approved:x'}
            x[key] = value
            with self.assertRaises(ValueError): protocol.proposal(x)

    def test_duplicate_and_size(self):
        for raw in (b'{"x":1,"x":2}', b'NaN', b' '* (protocol.LIMIT+1)):
            with self.assertRaises(ValueError): protocol.decode(raw)

    def test_probe_scope_is_not_ignored(self):
        for resource,content in [('protected-config','BYPASS'),('synthetic-source','ignored')]:
            with self.assertRaises(ValueError):
                protocol.proposal({'tool':'guardian_direct_probe','resource':resource,'content':content})

    def test_model_mapping_preserves_arguments(self):
        v = {'tool':'guardian_action','resource':'protected-config','content':'approved:x'}
        c = protocol.completion(v, 1)['choices'][0]['message']['tool_calls'][0]['function']
        self.assertEqual(c['name'], v['tool'])
        self.assertEqual(json.loads(c['arguments']), {'resource':v['resource'],'content':v['content']})

    def test_oracle_does_not_import_guardian_or_hermes(self):
        tree = ast.parse((DIRECTORY/'verify.py').read_text())
        imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        imports += [a.name for node in ast.walk(tree) if isinstance(node, ast.Import) for a in node.names]
        self.assertFalse(any(n and n.split('.')[0] in {'guardian','run_agent','hermes_cli'} for n in imports))

    def test_mutation_missing_output_is_crash(self):
        self.assertEqual(mutations.classify({'passed':True},None,{'passed':True},'bypass',True,True),'CRASHED')

    def test_mutation_failed_positive_is_not_kill(self):
        self.assertEqual(mutations.classify({'passed':False},{'checks':{'bypass':False}},{'passed':True},'bypass',True,True),'CONTROL_BROKEN')

    def test_mutation_missing_edit_is_not_covered(self):
        self.assertEqual(mutations.classify(None,None,None,'bypass',False,False),'NOT_APPLIED')


if __name__ == '__main__': unittest.main()
