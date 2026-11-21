"""PR1 native transition: preserve the old run and require a live-pipe replacement."""
from pathlib import Path
import argparse
import json
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return json.loads(path.read_bytes()) if path.is_file() else None


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n', encoding='utf-8', newline='\n')


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
            'normal': {'KILLED': 5, 'SURVIVED': 0, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0},
            'repeat': {'KILLED': 5, 'SURVIVED': 0, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0},
            'optimized': {'KILLED': 5, 'SURVIVED': 0, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0},
        }
        and v02.get('mutations') == {'KILLED': 11, 'SURVIVED': 0, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0}
        and v03.get('mutations') == {
            'normal': {'KILLED': 3, 'SURVIVED': 1, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0},
            'optimized': {'KILLED': 3, 'SURVIVED': 1, 'CRASHED': 0, 'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0},
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


def run(out, frozen):
    out = out.resolve(); frozen = frozen.resolve()
    if out.exists(): raise ValueError('fresh output directory required')
    out.mkdir(parents=True)
    rows = []
    rows.append(execute('historical-full-v04', [
        sys.executable, '-B', frozen/'tools/validate_v04.py', '--out', out/'historical',
    ], frozen, out, 9000))
    for mode, flags in [('normal', []), ('repeat', []), ('optimized', ['-O'])]:
        rows.append(execute('availability-'+mode, [
            sys.executable, '-B', *flags, ROOT/'tools/pr1_availability_witness_v1.py',
            '--frozen', frozen, '--out', out/('availability-'+mode), '--mode', mode,
        ], ROOT, out, 180))
    historical = historical_contract(out/'historical')
    availability = {mode: load(out/('availability-'+mode)/'report.json')
                    for mode in ('normal', 'repeat', 'optimized')}
    replacement_pass = all(report and report.get('passed') for report in availability.values())
    passed = historical['valid'] and replacement_pass
    report = {
        'schema': 'guardian.pr1-native-transition.v1',
        'status': 'PASS_LOCAL' if passed else 'HOLD', 'passed': passed,
        'historical': historical, 'replacement': {
            'passed': replacement_pass,
            'modes': {mode: (report or {}).get('cases') for mode, report in availability.items()},
        },
        'commands': rows,
        'rule': 'The old WinError2 is preserved as a failed historical availability control. It is never an ACL pass; current PASS requires the synchronized live-pipe witness and its ACL-removal control in all modes.',
        'production': 'HOLD', 'external_review': 'NOT_ESTABLISHED',
    }
    save(out/'report.json', report)
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--out', type=Path, required=True); p.add_argument('--frozen', type=Path, required=True); a = p.parse_args()
    raise SystemExit(0 if run(a.out, a.frozen)['passed'] else 1)
