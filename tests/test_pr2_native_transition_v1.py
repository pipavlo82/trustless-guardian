import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools.pr2_native_gate_v1 import count, historical_contract


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value)+'\n', encoding='utf-8', newline='\n')


def mutation_row(classification='CONTROL_BROKEN'):
    return {
        'applied': True, 'case': 'runtime_after_write',
        'classification': classification, 'id': 'ordinary_exception_legacy',
        'legacy_dispatch': True,
        'mutated_sha256': '9248ac75e5a6ea468f101b61380be8253d4ba4cb1bd9d0c4389825b246457cf9',
        'original_sha256': 'e2084614efe452c35533815de52de1508b6ab119b5e3395a47e29789c43f75c0',
        'restored_byte_exact': True, 'source': 'guardian/hardened.py',
    }


def scenario(passed, no_false):
    return {'passed': passed, 'scenarios': [{
        'case': 'runtime_after_write', 'passed': passed,
        'checks': {'no_false_nonexecution': no_false},
    }]}


def fixture(root):
    names = [
        'v03-regression', 'normal', 'repeat', 'optimized',
        'v0-mutations-repeat', 'v0-mutations-optimized',
        'v02-mutations-repeat', 'v02-mutations-optimized',
        'v03-mutations-repeat', 'v03-mutations-optimized',
        'mutations-normal', 'mutations-repeat', 'mutations-optimized',
    ]
    write(root/'report.json', {
        'passed': False,
        'commands': [{'name': name, 'exit_code': int(name == 'mutations-repeat')}
                     for name in names],
        'mutations': {
            'normal': count(killed=5), 'optimized': count(killed=5),
            'repeat': count(killed=4, control_broken=1),
        },
    })
    write(root/'v03/report.json', {
        'passed': True, 'commands': [{'name': 'v02-regression', 'exit_code': 0}],
        'mutations': {'normal': count(killed=3, survived=1),
                      'optimized': count(killed=3, survived=1)},
    })
    write(root/'v03/v02/report.json', {
        'passed': True, 'commands': [{'name': 'v0-regression', 'exit_code': 0}],
        'mutations': count(killed=11),
    })
    for mode in ('normal', 'repeat', 'optimized'):
        write(root/mode/'report.json', {'passed': True, 'scenarios': [{}]*15})
        counts = count(killed=4, control_broken=1) if mode == 'repeat' else count(killed=5)
        rows = [mutation_row()] if mode == 'repeat' else []
        write(root/('mutations-'+mode)/'report.json', {'counts': counts, 'mutants': rows})
    case = root/'mutations-repeat/ordinary_exception_legacy'
    write(case/'baseline/report.json', scenario(True, True))
    write(case/'mutated/report.json', scenario(False, False))
    write(case/'restored/report.json', scenario(False, False))
    write(case/'mutated/runtime_after_write/negative.client.json', {
        'response': {'execution': 'NOT_EXECUTED', 'reason': 'RuntimeError: V04_RUNTIME'},
    })
    write(case/'restored/runtime_after_write/negative.client.json', {
        'error': 'TimeoutError: IPC_TIMEOUT_CANCELLED',
    })
    write(case/'restored/runtime_after_write/negative.server.json', [{
        'response': {'execution': 'RECOVERY_REQUIRED', 'failure_stage': 'WRITTEN'},
    }])
    write(case/'restored/runtime_after_write/fault.json', {
        'events': [{'boundary': 'after_actual_write'}],
    })


class HistoricalContractTests(unittest.TestCase):
    def test_exact_raw_control_broken_is_preserved(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); fixture(root)
            result = historical_contract(root)
            self.assertTrue(result['valid'])
            self.assertEqual(result['status'], 'EXACT_KNOWN_RESTORED_CLIENT_TIMEOUT')

    def test_different_restored_error_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); fixture(root)
            path = root/'mutations-repeat/ordinary_exception_legacy/restored/runtime_after_write/negative.client.json'
            write(path, {'error': 'different'})
            self.assertFalse(historical_contract(root)['valid'])

    def test_missing_mutation_failure_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); fixture(root)
            report = json.loads((root/'mutations-repeat/report.json').read_bytes())
            report['mutants'][0]['classification'] = 'KILLED'
            write(root/'mutations-repeat/report.json', report)
            self.assertFalse(historical_contract(root)['valid'])

    def test_selected_native_baseline_keeps_raw_failure(self):
        root = Path(__file__).resolve().parents[1]
        selected = root/'research/stack_ci_transition_v1/pr2_native_baseline'
        result = historical_contract(selected)
        self.assertTrue(result['valid'])
        self.assertFalse(result['raw_root_passed'])
        self.assertTrue(result['known_failure_evidence_valid'])


if __name__ == '__main__':
    unittest.main()
