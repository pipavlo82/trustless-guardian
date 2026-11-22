"""PR2 native transition: source-bound prior evidence plus a timed physical witness."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
FROZEN = '03f6ffc6f4b983cfcc39f401f47165021e67e673'
BASELINE = ROOT/'research/stack_ci_transition_v1/PR2_NATIVE_BASELINE.json'
ZERO = {'KILLED': 0, 'SURVIVED': 0, 'CRASHED': 0,
        'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0}


def load(path):
    return json.loads(path.read_bytes()) if path.is_file() else None


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n',
                    encoding='utf-8', newline='\n')


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def execute(name, argv, cwd, out, timeout):
    started = time.time()
    try:
        run = subprocess.run([str(x) for x in argv], cwd=cwd,
                             capture_output=True, timeout=timeout)
        code = run.returncode; stdout = run.stdout; stderr = run.stderr
    except subprocess.TimeoutExpired as exc:
        code = 124; stdout = exc.stdout or b''
        stderr = (exc.stderr or b'')+b'\nTIMEOUT_NOT_A_PASS\n'
    (out/(name+'.stdout')).write_bytes(stdout)
    (out/(name+'.stderr')).write_bytes(stderr)
    row = {'name': name, 'argv': [str(x) for x in argv], 'cwd': str(cwd),
           'exit_code': code, 'started_unix': started,
           'seconds': time.time()-started}
    save(out/(name+'.command.json'), row); print(json.dumps(row), flush=True)
    return row


def command_codes(report):
    return {row['name']: row['exit_code'] for row in (report or {}).get('commands', [])}


def count(killed=0, survived=0, control_broken=0):
    return {'KILLED': killed, 'SURVIVED': survived, 'CRASHED': 0,
            'NOT_APPLIED': 0, 'CONTROL_BROKEN': control_broken}


def controls(report):
    if not report or len(report.get('scenarios', [])) != 1:
        return None
    return report['scenarios'][0]


def historical_contract(history):
    root = load(history/'report.json')
    v03 = load(history/'v03/report.json')
    v02 = load(history/'v03/v02/report.json')
    reports = {mode: load(history/mode/'report.json')
               for mode in ('normal', 'repeat', 'optimized')}
    mutations = {mode: load(history/('mutations-'+mode)/'report.json')
                 for mode in ('normal', 'repeat', 'optimized')}
    if not root or not v03 or not v02 or not all(reports.values()) or not all(mutations.values()):
        return {'valid': False, 'reason': 'MISSING_HISTORICAL_REPORT'}

    expected_root_commands = {
        'v03-regression', 'normal', 'repeat', 'optimized',
        'v0-mutations-repeat', 'v0-mutations-optimized',
        'v02-mutations-repeat', 'v02-mutations-optimized',
        'v03-mutations-repeat', 'v03-mutations-optimized',
        'mutations-normal', 'mutations-repeat', 'mutations-optimized',
    }
    root_codes = command_codes(root)
    command_chain_valid = (
        set(root_codes) == expected_root_commands
        and {name for name, code in root_codes.items() if code != 0} == {'mutations-repeat'}
        and v03.get('passed') is True and all(code == 0 for code in command_codes(v03).values())
        and v02.get('passed') is True and all(code == 0 for code in command_codes(v02).values())
    )
    v04_expected = {
        'normal': count(killed=5),
        'optimized': count(killed=5),
        'repeat': count(killed=4, control_broken=1),
    }
    mutation_counts_valid = (
        root.get('mutations') == v04_expected
        and v03.get('mutations') == {
            'normal': count(killed=3, survived=1),
            'optimized': count(killed=3, survived=1),
        }
        and v02.get('mutations') == count(killed=11)
        and mutations['normal'].get('counts') == count(killed=5)
        and mutations['optimized'].get('counts') == count(killed=5)
        and mutations['repeat'].get('counts') == count(killed=4, control_broken=1)
    )
    scenario_reports_valid = all(
        report.get('passed') is True and len(report.get('scenarios', [])) == 15
        for report in reports.values()
    )
    repeat_rows = mutations['repeat'].get('mutants', [])
    known = [row for row in repeat_rows if row.get('classification') != 'KILLED']
    known_row_valid = known == [{
        'applied': True,
        'case': 'runtime_after_write',
        'classification': 'CONTROL_BROKEN',
        'id': 'ordinary_exception_legacy',
        'legacy_dispatch': True,
        'mutated_sha256': '9248ac75e5a6ea468f101b61380be8253d4ba4cb1bd9d0c4389825b246457cf9',
        'original_sha256': 'e2084614efe452c35533815de52de1508b6ab119b5e3395a47e29789c43f75c0',
        'restored_byte_exact': True,
        'source': 'guardian/hardened.py',
    }]

    case_root = history/'mutations-repeat/ordinary_exception_legacy'
    baseline = controls(load(case_root/'baseline/report.json'))
    mutated = controls(load(case_root/'mutated/report.json'))
    restored = controls(load(case_root/'restored/report.json'))
    restored_client = load(case_root/'restored/runtime_after_write/negative.client.json') or {}
    restored_server = load(case_root/'restored/runtime_after_write/negative.server.json') or []
    mutated_client = load(case_root/'mutated/runtime_after_write/negative.client.json') or {}
    restored_fault = load(case_root/'restored/runtime_after_write/fault.json') or {}
    failure_exact = (
        baseline and baseline.get('passed') is True
        and mutated and mutated.get('passed') is False
        and mutated.get('checks', {}).get('no_false_nonexecution') is False
        and restored and restored.get('passed') is False
        and restored.get('checks', {}).get('no_false_nonexecution') is False
        and mutated_client.get('response', {}).get('execution') == 'NOT_EXECUTED'
        and 'RuntimeError: V04_RUNTIME' in mutated_client.get('response', {}).get('reason', '')
        and restored_client.get('error') == 'TimeoutError: IPC_TIMEOUT_CANCELLED'
        and len(restored_server) == 1
        and restored_server[0].get('response', {}).get('execution') == 'RECOVERY_REQUIRED'
        and restored_server[0].get('response', {}).get('failure_stage') == 'WRITTEN'
        and restored_fault.get('events') == [{'boundary': 'after_actual_write'}]
    )
    valid = (
        root.get('passed') is False and command_chain_valid
        and mutation_counts_valid and scenario_reports_valid
        and known_row_valid and failure_exact
    )
    return {
        'valid': bool(valid), 'raw_root_passed': root.get('passed'),
        'status': 'EXACT_KNOWN_RESTORED_CLIENT_TIMEOUT' if valid else 'UNEXPECTED_FAILURE_SET',
        'command_chain_valid': command_chain_valid,
        'mutation_populations_valid': mutation_counts_valid,
        'scenario_reports_valid': scenario_reports_valid,
        'known_failure_row_valid': known_row_valid,
        'known_failure_evidence_valid': failure_exact,
        'known_failure': known[0] if len(known) == 1 else known,
    }


def baseline_contract(frozen):
    baseline = load(BASELINE)
    if not baseline or baseline.get('schema') != 'guardian.pr2-native-baseline.v1':
        return {'valid': False, 'reason': 'BASELINE_SCHEMA'}
    selected = ROOT/baseline['selected_evidence_root']
    hashes = baseline.get('selected_artifact_sha256', {})
    artifact_mismatches = []
    for relative, expected in hashes.items():
        path = selected/relative
        actual = sha256_bytes(path.read_bytes()) if path.is_file() else None
        if actual != expected:
            artifact_mismatches.append(relative)
    seal_input = b''.join(relative.encode()+b'\0'+hashes[relative].encode()+b'\n'
                          for relative in sorted(hashes))
    seal_valid = sha256_bytes(seal_input) == baseline.get('selected_artifact_set_sha256')
    head = subprocess.check_output(['git', '-C', str(frozen), 'rev-parse', 'HEAD']).decode().strip()
    status = subprocess.check_output(['git', '-C', str(frozen), 'status', '--porcelain']).decode()
    expected_sources = baseline.get('source_sha256', {})
    actual_names = {
        path.relative_to(frozen).as_posix()
        for folder in ('guardian', 'tools', 'tests')
        for path in (frozen/folder).rglob('*.py')
    }
    source_mismatches = []
    for relative, expected in expected_sources.items():
        path = frozen/relative
        actual = sha256_bytes(path.read_bytes()) if path.is_file() else None
        if actual != expected:
            source_mismatches.append(relative)
    source_set_valid = actual_names == set(expected_sources)
    historical = historical_contract(selected)
    valid = (
        head == FROZEN and not status and not artifact_mismatches and seal_valid
        and not source_mismatches and source_set_valid and historical.get('valid')
    )
    return {
        'valid': bool(valid), 'classification': baseline.get('classification'),
        'baseline_sha256': sha256_bytes(BASELINE.read_bytes()),
        'selected_artifact_set_sha256': baseline.get('selected_artifact_set_sha256'),
        'selected_artifacts_verified': len(hashes)-len(artifact_mismatches),
        'selected_artifact_mismatches': artifact_mismatches,
        'frozen_head': head, 'frozen_status': status,
        'source_files_verified': len(expected_sources)-len(source_mismatches),
        'source_set_valid': source_set_valid, 'source_mismatches': source_mismatches,
        'historical': historical, 'limitations': baseline.get('limitations'),
    }


def run(out, frozen):
    out = out.resolve(); frozen = frozen.resolve()
    if out.exists():
        raise ValueError('fresh output directory required')
    out.mkdir(parents=True)
    rows = []
    for mode, flags in [('normal', []), ('repeat', []), ('optimized', ['-O'])]:
        rows.append(execute('ordinary-exception-'+mode, [
            sys.executable, '-B', *flags,
            ROOT/'tools/pr2_ordinary_exception_witness_v1.py',
            '--frozen', frozen, '--out', out/('ordinary-exception-'+mode),
            '--mode', mode,
        ], ROOT, out, 720))
    baseline = baseline_contract(frozen)
    witnesses = {
        mode: load(out/('ordinary-exception-'+mode)/'report.json')
        for mode in ('normal', 'repeat', 'optimized')
    }
    replacement_pass = all(
        report and report.get('passed') is True
        and report.get('classification') == 'KILLED'
        and report.get('source_restored') is True
        for report in witnesses.values()
    )
    passed = baseline['valid'] and replacement_pass and all(row['exit_code'] == 0 for row in rows)
    report = {
        'schema': 'guardian.pr2-native-transition.v1',
        'status': 'PASS_COMPOSITE_LOCAL' if passed else 'HOLD',
        'passed': passed,
        'evidence_mode': 'SOURCE_BOUND_PRIOR_WINDOWS_GATES_PLUS_CURRENT_WINDOWS_PHYSICAL_MUTATION',
        'historical_baseline': baseline,
        'replacement': {
            'passed': replacement_pass,
            'modes': {mode: (value or {}).get('classification')
                      for mode, value in witnesses.items()},
            'reports': witnesses,
        },
        'commands': rows,
        'rule': 'The old repeat CONTROL_BROKEN remains raw. Current PASS separately requires baseline, the same physical ordinary-exception mutation killed by observed false NOT_EXECUTED, byte-exact restoration, and passing restored control in normal/repeat/optimized modes.',
        'exact_final_full_historical_replay': False,
        'production': 'HOLD', 'external_review': 'NOT_ESTABLISHED',
    }
    save(out/'report.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--frozen', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if run(args.out, args.frozen)['passed'] else 1)
