import json
from pathlib import Path
import tempfile
import unittest

from tools.pr1_native_gate_v1 import historical_contract


V04 = {mode: {'KILLED': 5, 'SURVIVED': 0, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0}
       for mode in ('normal', 'repeat', 'optimized')}
V03 = {mode: {'KILLED': 3, 'SURVIVED': 1, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0}
       for mode in ('normal', 'optimized')}
V02 = {'KILLED': 11, 'SURVIVED': 0, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value)+'\n', encoding='utf-8', newline='\n')


def fixture(root, failure=None, extra_v02_failure=False):
    failed_modes = {failure['mode']} if failure else set()
    write(root/'report.json', {
        'passed': not failure, 'mutations': V04,
        'commands': [{'name': 'v03-regression', 'exit_code': int(bool(failure))},
                     {'name': 'normal', 'exit_code': 0}],
    })
    write(root/'v03/report.json', {
        'mutations': V03,
        'commands': [{'name': 'v02-regression', 'exit_code': int(bool(failure))},
                     {'name': 'normal', 'exit_code': 0}],
    })
    v02_commands = [
        {'name': 'v02-'+mode, 'exit_code': int(mode in failed_modes)}
        for mode in ('normal', 'repeat', 'optimized')
    ]
    if extra_v02_failure: v02_commands.append({'name': 'v02-mutations', 'exit_code': 1})
    write(root/'v03/v02/report.json', {'mutations': V02, 'commands': v02_commands})
    for mode in ('normal', 'repeat', 'optimized'):
        rows = []
        if failure and failure['mode'] == mode:
            rows.append({'name': failure['name'], 'passed': False, 'winerror': failure['winerror']})
        write(root/'v03/v02'/mode/'report.json', {'cases': rows})


class HistoricalContractTests(unittest.TestCase):
    def test_exact_winerror2_is_preserved_only_as_known_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); fixture(root, {'mode': 'repeat', 'name': 'unauthorized_pipe_client', 'winerror': 2})
            result = historical_contract(root)
            self.assertTrue(result['valid'])
            self.assertFalse(result['original_passed'])
            self.assertEqual(result['status'], 'EXACT_KNOWN_AVAILABILITY_FAILURE')

    def test_different_failure_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); fixture(root, {'mode': 'repeat', 'name': 'unauthorized_pipe_client', 'winerror': 3})
            self.assertFalse(historical_contract(root)['valid'])

    def test_selected_native_baseline_keeps_raw_failure_and_mutations(self):
        root = Path(__file__).resolve().parents[1]
        selected = root/'research/stack_ci_transition_v1/pr1_native_baseline'
        result = historical_contract(selected)
        self.assertTrue(result['valid'])
        self.assertEqual(result['status'], 'EXACT_KNOWN_AVAILABILITY_FAILURE')
        self.assertTrue(result['mutation_populations_valid'])

    def test_additional_nonzero_command_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); fixture(root, {'mode': 'repeat', 'name': 'unauthorized_pipe_client', 'winerror': 2}, True)
            self.assertFalse(historical_contract(root)['valid'])


if __name__ == '__main__':
    unittest.main()
