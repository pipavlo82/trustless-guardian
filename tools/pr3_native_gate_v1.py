"""Source-bound historical PR3 evidence plus targeted current Windows witnesses."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
FROZEN = '03f6ffc6f4b983cfcc39f401f47165021e67e673'
BASELINE = ROOT/'research/stack_ci_transition_v1/PR3_NATIVE_BASELINE.json'
ZERO = {'KILLED': 0, 'SURVIVED': 0, 'CRASHED': 0,
        'NOT_APPLIED': 0, 'CONTROL_BROKEN': 0}
CURRENT = [
    ('runtime-after-commit', 'v04_runtime_after_commit', 'normal'),
    ('committed-failure', 'v03_committed_failure', 'repeat'),
    ('ordinary-exception', 'v04_ordinary_exception_legacy', 'optimized'),
    ('recovery-response', 'v04_recovery_response', 'optimized'),
    ('dispatch-outcome', 'v04_dispatch_outcome', 'optimized'),
    ('readback-consistency', 'v04_readback_consistency', 'optimized'),
    ('same-bytes', 'v03_same_bytes', 'repeat'),
    ('resource-identity', 'v02_resource_identity', 'repeat'),
    ('directory-identity', 'v02_directory_identity', 'optimized'),
]


def load(path):
    return json.loads(path.read_bytes()) if path.is_file() else None


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n',
                    encoding='utf-8', newline='\n')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def count(killed=0, survived=0, control_broken=0):
    return {'KILLED': killed, 'SURVIVED': survived, 'CRASHED': 0,
            'NOT_APPLIED': 0, 'CONTROL_BROKEN': control_broken}


def command_codes(report):
    return {row['name']: row['exit_code'] for row in report.get('commands', [])}


def execute(name, argv, out, timeout=600):
    started = time.time()
    try:
        run = subprocess.run([str(x) for x in argv], cwd=ROOT,
                             capture_output=True, timeout=timeout)
        code = run.returncode; stdout = run.stdout; stderr = run.stderr
    except subprocess.TimeoutExpired as exc:
        code = 124; stdout = exc.stdout or b''
        stderr = (exc.stderr or b'')+b'\nTIMEOUT_NOT_A_PASS\n'
    (out/(name+'.stdout')).write_bytes(stdout)
    (out/(name+'.stderr')).write_bytes(stderr)
    row = {'name': name, 'argv': [str(x) for x in argv],
           'exit_code': code, 'started_unix': started,
           'seconds': time.time()-started}
    save(out/(name+'.command.json'), row); print(json.dumps(row), flush=True)
    return row


def failed_scenarios(report):
    return [row.get('case', row.get('name')) for row in report.get('scenarios', [])
            if not row.get('passed')]


def one_non_killed(report):
    return [row for row in report.get('mutants', [])
            if row.get('classification') != 'KILLED']


def historical_contract(history):
    required = {
        'root': history/'report.json', 'v03': history/'v03/report.json',
        'v02': history/'v03/v02/report.json',
        'normal': history/'normal/report.json',
        'repeat': history/'repeat/report.json',
        'optimized': history/'optimized/report.json',
        'v03-normal': history/'v03/normal/report.json',
        'v03-repeat': history/'v03/repeat/report.json',
        'v03-optimized': history/'v03/optimized/report.json',
        'v04-mut-opt': history/'mutations-optimized/report.json',
        'v03-mut-repeat': history/'v03-mutations-repeat/report.json',
        'v03-mut-opt': history/'v03-mutations-optimized/report.json',
        'v02-mut-repeat': history/'v02-mutations-repeat/report.json',
        'v02-mut-opt': history/'v02-mutations-optimized/report.json',
    }
    values = {name: load(path) for name, path in required.items()}
    if not all(values.values()):
        return {'valid': False, 'reason': 'MISSING_HISTORICAL_REPORT'}
    root = values['root']; v03 = values['v03']; v02 = values['v02']
    root_codes = {
        'v03-regression': 1, 'normal': 1, 'repeat': 0, 'optimized': 0,
        'v0-mutations-repeat': 0, 'v0-mutations-optimized': 0,
        'v02-mutations-repeat': 1, 'v02-mutations-optimized': 1,
        'v03-mutations-repeat': 1, 'v03-mutations-optimized': 0,
        'mutations-normal': 0, 'mutations-repeat': 0,
        'mutations-optimized': 1,
    }
    v03_codes = {
        'v02-regression': 0, 'runner-token': 0, 'harness-crash-control': 0,
        'normal': 0, 'repeat': 1, 'optimized': 0,
        'mutations-normal': 0, 'mutations-optimized': 0,
    }
    v02_codes = {'v0-regression': 0, 'handle-inheritance': 0,
                 'v02-normal': 0, 'v02-repeat': 0, 'v02-optimized': 0,
                 'v02-mutations': 0}
    command_chain = (command_codes(root) == root_codes
                     and command_codes(v03) == v03_codes
                     and command_codes(v02) == v02_codes)
    scenario_chain = (
        values['normal'].get('passed') is False
        and failed_scenarios(values['normal']) == ['runtime_after_commit']
        and values['repeat'].get('passed') is True
        and values['optimized'].get('passed') is True
        and all(len(values[name].get('scenarios', [])) == 15
                for name in ('normal', 'repeat', 'optimized'))
        and values['v03-normal'].get('passed') is True
        and values['v03-repeat'].get('passed') is False
        and failed_scenarios(values['v03-repeat']) == ['committed_failure']
        and values['v03-optimized'].get('passed') is True
        and all(len(values[name].get('scenarios', [])) == 21
                for name in ('v03-normal', 'v03-repeat', 'v03-optimized'))
        and v02.get('passed') is True
    )
    mutation_chain = (
        root.get('mutations') == {
            'normal': count(killed=5), 'repeat': count(killed=5),
            'optimized': count(killed=1, control_broken=4),
        }
        and v03.get('mutations') == {
            'normal': count(killed=3, survived=1),
            'optimized': count(killed=3, survived=1),
        }
        and v02.get('mutations') == count(killed=11)
        and values['v04-mut-opt'].get('counts') == count(killed=1, control_broken=4)
        and values['v03-mut-repeat'].get('counts') == count(killed=2, survived=1, control_broken=1)
        and values['v03-mut-opt'].get('counts') == count(killed=3, survived=1)
        and values['v02-mut-repeat'].get('counts') == count(killed=10, control_broken=1)
        and values['v02-mut-opt'].get('counts') == count(killed=10, survived=1)
    )

    v04_non = {(row['id'], row['classification'])
               for row in one_non_killed(values['v04-mut-opt'])}
    v03_repeat_non = {(row['id'], row['classification'], row.get('boundary_exercised'))
                      for row in one_non_killed(values['v03-mut-repeat'])}
    v03_opt_non = {(row['id'], row['classification'], row.get('boundary_exercised'))
                   for row in one_non_killed(values['v03-mut-opt'])}
    v02_repeat_non = {(row['id'], row['classification'])
                      for row in one_non_killed(values['v02-mut-repeat'])}
    v02_opt_non = {(row['id'], row['classification'])
                   for row in one_non_killed(values['v02-mut-opt'])}
    failure_set = (
        v04_non == {('ordinary_exception_legacy', 'CONTROL_BROKEN'),
                    ('recovery_response', 'CONTROL_BROKEN'),
                    ('dispatch_outcome', 'CONTROL_BROKEN'),
                    ('readback_consistency', 'CONTROL_BROKEN')}
        and v03_repeat_non == {('same_bytes', 'CONTROL_BROKEN', True),
                              ('impersonation_level', 'SURVIVED', False)}
        and v03_opt_non == {('impersonation_level', 'SURVIVED', False)}
        and v02_repeat_non == {('resource_identity', 'CONTROL_BROKEN')}
        and v02_opt_non == {('directory_identity', 'SURVIVED')}
    )

    runtime = load(history/'normal/runtime_after_commit/witness.json') or {}
    runtime_negative = load(history/'normal/runtime_after_commit/negative.server.json') or []
    runtime_fault = load(history/'normal/runtime_after_commit/fault.json') or {}
    runtime_exact = (
        "JSONDecodeError" in str(runtime.get('control_broken'))
        and len(runtime_negative) == 1
        and runtime_negative[0].get('response', {}).get('execution') == 'RECOVERY_REQUIRED'
        and runtime_negative[0].get('response', {}).get('failure_stage') == 'COMMITTED'
        and runtime_fault.get('events') == [{'boundary': 'after_actual_commit'}]
    )
    committed = load(history/'v03/repeat/committed_failure/witness.json') or {}
    committed_client = load(history/'v03/repeat/committed_failure/negative.client.json') or {}
    committed_server = load(history/'v03/repeat/committed_failure/negative.server.json') or []
    committed_exact = (
        committed.get('positive_ok') is True and committed.get('negative_ok') is False
        and committed_client.get('error') == 'TimeoutError: IPC_TIMEOUT_CANCELLED'
        and len(committed_server) == 1
        and committed_server[0].get('response', {}).get('execution') == 'RECOVERY_REQUIRED'
        and committed_server[0].get('response', {}).get('failure_stage') == 'COMMITTED'
    )
    same_restored = load(history/'v03-mutations-repeat/same_bytes/restored/command.json') or {}
    same_exact = same_restored.get('exit_code') == 1
    resource = load(history/'v02-mutations-repeat/resource_identity/mutated/witness.json') or {}
    resource_exact = (resource.get('positive_ok') is False
                      and resource.get('negative_wrote') is True)
    directory_exact = True
    for phase in ('baseline', 'mutated', 'restored'):
        witness = load(history/f'v02-mutations-optimized/directory_identity/{phase}/witness.json') or {}
        directory_exact = directory_exact and (
            witness.get('positive_ok') is True
            and witness.get('negative_wrote') is False
            and witness.get('negative', {}).get('response', {}).get('error') == 'BROKER_START_FAILED'
        )
    exact_failures = (runtime_exact and committed_exact and same_exact
                      and resource_exact and directory_exact)
    valid = (root.get('passed') is False and v03.get('passed') is False
             and command_chain and scenario_chain and mutation_chain
             and failure_set and exact_failures)
    return {
        'valid': bool(valid), 'raw_root_passed': root.get('passed'),
        'command_chain_valid': command_chain,
        'scenario_chain_valid': scenario_chain,
        'mutation_chain_valid': mutation_chain,
        'raw_failure_set_valid': failure_set,
        'exact_failure_evidence_valid': exact_failures,
        'historical_impersonation_survivor_preserved': True,
    }


def baseline_contract(frozen):
    baseline = load(BASELINE)
    if not baseline or baseline.get('schema') != 'guardian.pr3-native-baseline.v1':
        return {'valid': False, 'reason': 'BASELINE_SCHEMA'}
    selected = ROOT/baseline['selected_evidence_root']
    hashes = baseline.get('selected_artifact_sha256', {})
    artifact_mismatches = []
    for relative, expected in hashes.items():
        path = selected/relative
        actual = sha(path.read_bytes()) if path.is_file() else None
        if actual != expected:
            artifact_mismatches.append(relative)
    seal_input = b''.join(relative.encode()+b'\0'+hashes[relative].encode()+b'\n'
                          for relative in sorted(hashes))
    seal_valid = sha(seal_input) == baseline.get('selected_artifact_set_sha256')
    head = subprocess.check_output(['git', '-C', str(frozen), 'rev-parse', 'HEAD'],
                                   text=True).strip()
    status = subprocess.check_output(['git', '-C', str(frozen), 'status', '--porcelain'],
                                     text=True)
    expected_sources = baseline.get('source_sha256', {})
    actual_names = {path.relative_to(frozen).as_posix()
                    for folder in ('guardian', 'tools', 'tests')
                    for path in (frozen/folder).rglob('*.py')}
    source_mismatches = []
    for relative, expected in expected_sources.items():
        path = frozen/relative
        actual = sha(path.read_bytes()) if path.is_file() else None
        if actual != expected:
            source_mismatches.append(relative)
    source_set_valid = actual_names == set(expected_sources)
    historical = historical_contract(selected)
    valid = (head == FROZEN and not status and not artifact_mismatches
             and seal_valid and not source_mismatches and source_set_valid
             and historical.get('valid'))
    return {
        'valid': bool(valid), 'classification': baseline.get('classification'),
        'baseline_sha256': sha(BASELINE.read_bytes()),
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
    commands = []
    for name, case, mode in CURRENT:
        commands.append(execute(name, [
            sys.executable, '-B', ROOT/'tools/pr3_native_witness_v1.py',
            '--frozen', frozen, '--out', out/name, '--case', case, '--mode', mode,
        ], out))
    baseline = baseline_contract(frozen)
    witnesses = {name: load(out/name/'report.json') for name, _, _ in CURRENT}
    replacement_pass = all(value and value.get('passed') is True
                           for value in witnesses.values())
    overlay_hashes = {value.get('harness_overlay_sha256')
                      for value in witnesses.values() if value}
    overlay_consistent = len(overlay_hashes) == 1
    passed = (baseline.get('valid') and replacement_pass and overlay_consistent
              and all(row['exit_code'] == 0 for row in commands))
    report = {
        'schema': 'guardian.pr3-native-transition.v1',
        'status': 'PASS_COMPOSITE_LOCAL' if passed else 'HOLD',
        'passed': bool(passed),
        'evidence_mode': 'SOURCE_BOUND_PRIOR_WINDOWS_GATES_PLUS_CURRENT_TARGETED_WINDOWS_WITNESSES',
        'historical_baseline': baseline,
        'replacement': {
            'passed': replacement_pass, 'harness_overlay_consistent': overlay_consistent,
            'harness_overlay_sha256': next(iter(overlay_hashes)) if overlay_consistent else None,
            'results': {name: {'passed': value.get('passed'),
                               'classification': value.get('classification'),
                               'source_restored': value.get('source_restored')}
                        for name, value in witnesses.items()},
        },
        'commands': commands,
        'rule': 'Historical failures and survivors remain raw. Current PASS separately requires the same source-bound scenarios and physical mutations to pass under one recorded disposable test-harness overlay; mutation sources must restore byte-exactly.',
        'historical_impersonation_level_survivor': 'PRESERVED_NOT_RECLASSIFIED',
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
