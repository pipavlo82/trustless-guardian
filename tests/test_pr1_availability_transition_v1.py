import json
from pathlib import Path
import tempfile
import unittest

from tools.pr1_native_gate_v1 import historical_contract, timing_adjusted_bytes


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

    def test_timing_adjustment_changes_only_unauthorized_window(self):
        source = (b"prefix\n    row=lab.roundtrip('unauthorized_pipe_client',lab.request('unauthorized'),"
                  b"container=lab.other,server_options={'timeout_ms':500})\n"
                  b"    row=lab.roundtrip('idle_client',server_options={'timeout_ms':500},fixture_idle=True)\n")
        adjusted = timing_adjusted_bytes(source)
        self.assertIn(b"unauthorized'),container=lab.other,server_options={'timeout_ms':5000}", adjusted)
        self.assertIn(b"'idle_client',server_options={'timeout_ms':500}", adjusted)
        self.assertEqual(len(source), len(adjusted)-1)

    def test_timing_adjustment_rejects_missing_or_duplicate_target(self):
        target = (b"row=lab.roundtrip('unauthorized_pipe_client',lab.request('unauthorized'),"
                  b"container=lab.other,server_options={'timeout_ms':500})")
        with self.assertRaises(ValueError):
            timing_adjusted_bytes(b'no target')
        with self.assertRaises(ValueError):
            timing_adjusted_bytes(target+b'\n'+target)

    def test_additional_nonzero_command_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); fixture(root, {'mode': 'repeat', 'name': 'unauthorized_pipe_client', 'winerror': 2}, True)
            self.assertFalse(historical_contract(root)['valid'])


if __name__ == '__main__':
    unittest.main()
