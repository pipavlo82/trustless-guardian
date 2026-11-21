"""PR1 native transition: source-bound prior evidence plus a live-pipe replacement."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
FROZEN = '03f6ffc6f4b983cfcc39f401f47165021e67e673'
BASELINE = ROOT/'research/stack_ci_transition_v1/PR1_NATIVE_BASELINE.json'


def load(path):
    return json.loads(path.read_bytes()) if path.is_file() else None


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n', encoding='utf-8', newline='\n')


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def execute(name, argv, cwd, out, timeout):
    started = time.time()
    try:
        run = subprocess.run([str(x) for x in argv], cwd=cwd, capture_output=True, timeout=timeout)
        code = run.returncode; stdout = run.stdout; stderr = run.stderr
    except subprocess.TimeoutExpired as exc:
        code = 124; stdout = exc.stdout or b''; stderr = (exc.stderr or b'')+b'\nTIMEOUT_NOT_A_PASS\n'
    (out/(name+'.stdout')).write_bytes(stdout); (out/(name+'.stderr')).write_bytes(stderr)
    row = {'name': name, 'argv': [str(x) for x in argv], 'cwd': str(cwd),
           'exit_code': code, 'started_unix': started, 'seconds': time.time()-started}
    save(out/(name+'.command.json'), row); print(json.dumps(row), flush=True)
    return row


def commands(report):
    return {row['name']: row['exit_code'] for row in (report or {}).get('commands', [])}


def historical_contract(history):
    root = load(history/'report.json')
    v03 = load(history/'v03/report.json')
    v02 = load(history/'v03/v02/report.json')
    if not all((root, v03, v02)):
        return {'valid': False, 'reason': 'MISSING_HISTORICAL_REPORT'}
    scenario_failures = []
    for mode in ('normal', 'repeat', 'optimized'):
        report = load(history/'v03/v02'/mode/'report.json')
        if not report: return {'valid': False, 'reason': 'MISSING_V02_'+mode.upper()}
        for row in report.get('cases', []):
            if row.get('passed') is False:
                scenario_failures.append({'mode': mode, **row})
    unexpected = [row for row in scenario_failures
                  if row.get('name') != 'unauthorized_pipe_client' or row.get('winerror') != 2]
    failed_modes = {row['mode'] for row in scenario_failures}
    expected_v02_nonzero = {'v02-'+mode for mode in failed_modes}
    actual_v02_nonzero = {name for name, code in commands(v02).items() if code != 0}
    actual_v03_nonzero = {name for name, code in commands(v03).items() if code != 0}
    actual_root_nonzero = {name for name, code in commands(root).items() if code != 0}
    chain_ok = (
        actual_v02_nonzero == expected_v02_nonzero
        and actual_v03_nonzero == ({'v02-regression'} if failed_modes else set())
        and actual_root_nonzero == ({'v03-regression'} if failed_modes else set())
    )
    mutation_ok = (
        root.get('mutations') == {
            mode: {'KILLED': 5, 'SURVIVED': 0, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0}
            for mode in ('normal', 'repeat', 'optimized')
        }
        and v02.get('mutations') == {'KILLED': 11, 'SURVIVED': 0, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0}
        and v03.get('mutations') == {
            mode: {'KILLED': 3, 'SURVIVED': 1, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0}
            for mode in ('normal', 'optimized')
        }
    )
    original_pass = not scenario_failures and root.get('passed') is True
    exact_known_failure = bool(scenario_failures) and not unexpected and chain_ok
    return {
        'valid': mutation_ok and chain_ok and (original_pass or exact_known_failure),
        'original_passed': original_pass,
        'status': 'PASS' if original_pass else 'EXACT_KNOWN_AVAILABILITY_FAILURE',
        'scenario_failures': scenario_failures, 'unexpected_failures': unexpected,
        'command_chain_valid': chain_ok, 'mutation_populations_valid': mutation_ok,
        'raw_root_passed': root.get('passed'),
    }


def baseline_contract(frozen):
    baseline = load(BASELINE)
    if not baseline or baseline.get('schema') != 'guardian.pr1-native-baseline.v1':
        return {'valid': False, 'reason': 'BASELINE_SCHEMA'}
    selected = ROOT/baseline['selected_evidence_root']
    hashes = baseline.get('selected_artifact_sha256', {})
    artifact_mismatches = []
    for relative, expected in hashes.items():
        path = selected/relative
        actual = sha256_bytes(path.read_bytes()) if path.is_file() else None
        if actual != expected: artifact_mismatches.append(relative)
    seal_input = b''.join(relative.encode()+b'\0'+hashes[relative].encode()+b'\n'
                          for relative in sorted(hashes))
    seal_valid = sha256_bytes(seal_input) == baseline.get('selected_artifact_set_sha256')
    head = subprocess.check_output(['git', '-C', str(frozen), 'rev-parse', 'HEAD']).decode().strip()
    status = subprocess.check_output(['git', '-C', str(frozen), 'status', '--porcelain']).decode()
    expected_sources = baseline.get('source_sha256', {})
    actual_names = {path.relative_to(frozen).as_posix()
                    for folder in ('guardian', 'tools', 'tests')
                    for path in (frozen/folder).rglob('*.py')}
    source_mismatches = []
    for relative, expected in expected_sources.items():
        path = frozen/relative
        actual = sha256_bytes(path.read_bytes()) if path.is_file() else None
        if actual != expected: source_mismatches.append(relative)
    source_set_valid = actual_names == set(expected_sources)
    historical = historical_contract(selected)
    valid = (head == FROZEN and not status and not artifact_mismatches and seal_valid
             and not source_mismatches and source_set_valid and historical.get('valid'))
    return {
        'valid': bool(valid),
        'classification': baseline.get('classification'),
        'baseline_sha256': sha256_bytes(BASELINE.read_bytes()),
        'selected_artifact_set_sha256': baseline.get('selected_artifact_set_sha256'),
        'selected_artifacts_verified': len(hashes)-len(artifact_mismatches),
        'selected_artifact_mismatches': artifact_mismatches,
        'frozen_head': head, 'frozen_status': status,
        'source_files_verified': len(expected_sources)-len(source_mismatches),
        'source_set_valid': source_set_valid, 'source_mismatches': source_mismatches,
        'historical': historical,
        'limitations': baseline.get('limitations'),
    }


def run(out, frozen):
    out = out.resolve(); frozen = frozen.resolve()
    if out.exists(): raise ValueError('fresh output directory required')
    out.mkdir(parents=True)
    rows = []
    for mode, flags in [('normal', []), ('repeat', []), ('optimized', ['-O'])]:
        rows.append(execute('availability-'+mode, [
            sys.executable, '-B', *flags, ROOT/'tools/pr1_availability_witness_v1.py',
            '--frozen', frozen, '--out', out/('availability-'+mode), '--mode', mode,
        ], ROOT, out, 240))
    baseline = baseline_contract(frozen)
    availability = {mode: load(out/('availability-'+mode)/'report.json')
                    for mode in ('normal', 'repeat', 'optimized')}
    replacement_pass = all(report and report.get('passed') for report in availability.values())
    passed = baseline['valid'] and replacement_pass
    report = {
        'schema': 'guardian.pr1-native-transition.v1',
        'status': 'PASS_COMPOSITE_LOCAL' if passed else 'HOLD', 'passed': passed,
        'evidence_mode': 'SOURCE_BOUND_PRIOR_WINDOWS_MUTATIONS_PLUS_CURRENT_WINDOWS_AVAILABILITY',
        'historical_baseline': baseline,
        'replacement': {
            'passed': replacement_pass,
            'modes': {mode: (report or {}).get('cases') for mode, report in availability.items()},
        },
        'commands': rows,
        'rule': 'Prior Windows mutation evidence is accepted only when all 25 selected reports and every frozen Python source byte match. The old WinError2 remains failed; current PASS separately requires the synchronized live-pipe witness and ACL-removal control in all modes.',
        'exact_final_full_historical_replay': False,
        'production': 'HOLD', 'external_review': 'NOT_ESTABLISHED',
    }
    save(out/'report.json', report)
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--out', type=Path, required=True); p.add_argument('--frozen', type=Path, required=True); a = p.parse_args()
    raise SystemExit(0 if run(a.out, a.frozen)['passed'] else 1)
