import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.pr3_native_gate_v1 import historical_contract
from tools.pr3_native_witness_v1 import CASES, classify


ROOT = Path(__file__).resolve().parents[1]
SELECTED = ROOT/'research/stack_ci_transition_v1/pr3_native_baseline'


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n',
                    encoding='utf-8', newline='\n')


class HistoricalContractTests(unittest.TestCase):
    def test_exact_raw_failure_set_is_preserved(self):
        result = historical_contract(SELECTED)
        self.assertTrue(result['valid'])
        self.assertFalse(result['raw_root_passed'])
        self.assertTrue(result['raw_failure_set_valid'])
        self.assertTrue(result['historical_impersonation_survivor_preserved'])

    def test_rewriting_raw_scenario_failure_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw)/'evidence'; shutil.copytree(SELECTED, target)
            path = target/'normal/report.json'; report = json.loads(path.read_bytes())
            report['passed'] = True
            write(path, report)
            self.assertFalse(historical_contract(target)['valid'])

    def test_masked_directory_survivor_evidence_is_required(self):
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw)/'evidence'; shutil.copytree(SELECTED, target)
            path = target/'v02-mutations-optimized/directory_identity/mutated/witness.json'
            witness = json.loads(path.read_bytes())
            witness['negative']['response']['error'] = 'different'
            write(path, witness)
            self.assertFalse(historical_contract(target)['valid'])


class CurrentClassificationTests(unittest.TestCase):
    def test_v03_mutant_requires_healthy_restored_control(self):
        good = {'positive_ok': True, 'negative_ok': True}
        killed = {'positive_ok': True, 'negative_ok': False}
        self.assertEqual(classify(CASES['v03_same_bytes'], good, killed, good, True),
                         'KILLED')
        broken = {'positive_ok': True, 'negative_ok': False}
        self.assertEqual(classify(CASES['v03_same_bytes'], good, killed, broken, True),
                         'CONTROL_BROKEN')


if __name__ == '__main__':
    unittest.main()
