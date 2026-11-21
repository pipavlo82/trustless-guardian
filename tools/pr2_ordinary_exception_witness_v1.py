"""Physical baseline/mutant/restored witness for the PR2 native timing failure."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
FROZEN = '03f6ffc6f4b983cfcc39f401f47165021e67e673'
SOURCE = 'guardian/hardened.py'
OLD = 'except Exception:  # V04 ordinary_exception_boundary'
NEW = "except (OSError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,RecursionError,__import__('sqlite3').Error):  # V04 ordinary_exception_boundary"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n',
                    encoding='utf-8', newline='\n')


def phase(checkout, out):
    sys.path.insert(0, str(checkout))
    from guardian.policy import digest
    from tools.lab import write
    from tools import v04_campaign as campaign

    original_lab = campaign.Lab04

    class StableLab(original_lab):
        def __init__(self, target):
            super().__init__(target)
            shutil.copyfile(HERE/'pr2_ordinary_exception_worker_v1.py',
                            self.runtime/'pr2_ordinary_exception_worker_v1.py')
            self.acl(self.runtime/'pr2_ordinary_exception_worker_v1.py')

        def roundtrip(self, name, value=None, container=None, server_options=None, **options):
            server_options = {
                'timeout_ms': 15000, 'response_timeout_ms': 15000,
                **(server_options or {}),
            }
            options.setdefault('client_timeout_ms', 15000)
            return super().roundtrip(name, value, container, server_options, **options)

        def launch(self, container, cfg, name):
            path = self.runtime/(name+'.json'); write(path, cfg); self.acl(path)
            result = container.launch([
                self.runtime/'python.exe', '-B', *(['-O'] if sys.flags.optimize else []),
                self.runtime/'pr2_ordinary_exception_worker_v1.py', path,
            ], self.runtime, 30)
            result['token']['user_sid_sha256'] = digest(result['token'].pop('user_sid').encode())
            write(self.out/(name+'.process.json'), result)
            return result

    campaign.Lab04 = StableLab
    try:
        return campaign.witness('runtime_after_write', out, legacy=True)
    finally:
        campaign.Lab04 = original_lab


def execute_phase(checkout, out, mode, name):
    flags = ['-O'] if mode == 'optimized' else []
    argv = [sys.executable, '-B', *flags, Path(__file__).resolve(),
            '--phase', '--checkout', checkout, '--out', out]
    started = time.time()
    try:
        run = subprocess.run([str(x) for x in argv], cwd=ROOT,
                             capture_output=True, timeout=180)
        code = run.returncode; stdout = run.stdout; stderr = run.stderr
    except subprocess.TimeoutExpired as exc:
        code = 124; stdout = exc.stdout or b''
        stderr = (exc.stderr or b'')+b'\nTIMEOUT_NOT_A_PASS\n'
    out.parent.mkdir(parents=True, exist_ok=True)
    (out.parent/(name+'.stdout')).write_bytes(stdout)
    (out.parent/(name+'.stderr')).write_bytes(stderr)
    save(out.parent/(name+'.command.json'), {
        'argv': [str(x) for x in argv], 'exit_code': code,
        'started_unix': started, 'seconds': time.time()-started,
    })
    witness = out/'witness.json'
    return json.loads(witness.read_bytes()) if code in (0, 1) and witness.is_file() else None


def valid_control(value):
    if not value or value.get('control_broken'):
        return False
    checks = value.get('checks', {})
    return all(checks.get(key) for key in (
        'positive', 'controlled_process', 'host_digest', 'independent_host_bytes',
        'independent_broker_token', 'actual_bytes', 'durable_state', 'fault_reached',
        'restart_control', 'restart_preserves_ambiguity',
    ))


def observed_mutant_kill(path, value):
    client_path = path/'negative.client.json'
    server_path = path/'negative.server.json'
    if not client_path.is_file() or not server_path.is_file():
        return False
    client = json.loads(client_path.read_bytes())
    server = json.loads(server_path.read_bytes())
    response = client.get('response', {})
    server_response = server[0].get('response', {}) if server else {}
    return (
        valid_control(value) and value.get('passed') is False
        and value.get('checks', {}).get('no_false_nonexecution') is False
        and response.get('execution') == 'NOT_EXECUTED'
        and response.get('status') == 'REFUTED'
        and 'RuntimeError: V04_RUNTIME' in response.get('reason', '')
        and server_response == response
    )


def run(out, frozen, mode):
    out = out.resolve(); frozen = frozen.resolve()
    if out.exists():
        raise ValueError('fresh output directory required')
    out.mkdir(parents=True)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=frozen,
                                   text=True).strip()
    status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=frozen,
                                     text=True)
    if head != FROZEN or status:
        raise ValueError('FROZEN_SOURCE_REFUSED')
    runtime = frozen/'build/runtime/python-3.12.10-embed-amd64.zip'
    if not runtime.is_file():
        raise ValueError('PINNED_RUNTIME_MISSING')

    temp_root = Path(tempfile.mkdtemp(prefix='pr2-ordinary-', dir=out.parent))
    checkout = temp_root/'checkout'
    try:
        for folder in ('guardian', 'tools'):
            shutil.copytree(frozen/folder, checkout/folder,
                            ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copyfile(frozen/'runtime-lock.json', checkout/'runtime-lock.json')
        target_runtime = checkout/'build/runtime'/runtime.name
        target_runtime.parent.mkdir(parents=True)
        shutil.copyfile(runtime, target_runtime)

        source = checkout/SOURCE; original = source.read_bytes()
        text = original.decode()
        if text.count(OLD) != 1:
            raise ValueError('MUTATION_TARGET_NOT_UNIQUE')
        changed = text.replace(OLD, NEW).encode()
        baseline = execute_phase(checkout, out/'baseline', mode, 'baseline')
        source.write_bytes(changed)
        mutated = execute_phase(checkout, out/'mutated', mode, 'mutated')
        source.write_bytes(original)
        restored = execute_phase(checkout, out/'restored', mode, 'restored')
        source_restored = source.read_bytes() == original
        baseline_ok = valid_control(baseline) and baseline.get('passed') is True
        mutated_killed = observed_mutant_kill(out/'mutated', mutated)
        restored_ok = valid_control(restored) and restored.get('passed') is True
        passed = baseline_ok and mutated_killed and restored_ok and source_restored
        report = {
            'schema': 'guardian.pr2-ordinary-exception-witness.v1',
            'passed': passed, 'classification': 'KILLED' if passed else 'CONTROL_BROKEN',
            'mode': mode, 'frozen_sha': head, 'legacy_dispatch': True,
            'physical_mutation_applied': True, 'source': SOURCE,
            'original_sha256': sha(original), 'mutated_sha256': sha(changed),
            'source_restored': source_restored,
            'phases': {
                'baseline': {'passed': baseline_ok, 'witness': baseline},
                'mutated': {'killed': mutated_killed, 'witness': mutated},
                'restored': {'passed': restored_ok, 'witness': restored},
            },
            'timeouts_ms': {'server': 15000, 'response': 15000, 'client': 15000},
            'meaning': 'The broad ordinary exception boundary returns RECOVERY_REQUIRED after a write; physically removing RuntimeError handling falsely reports NOT_EXECUTED. Baseline and byte-exact restoration must both pass.',
            'historical_raw_classification': 'CONTROL_BROKEN_PRESERVED_SEPARATELY',
            'production': 'HOLD', 'external_review': 'NOT_ESTABLISHED',
        }
        save(out/'report.json', report)
        return report
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--frozen', type=Path)
    parser.add_argument('--mode', choices=('normal', 'repeat', 'optimized'))
    parser.add_argument('--phase', action='store_true')
    parser.add_argument('--checkout', type=Path)
    args = parser.parse_args()
    if args.phase:
        if args.checkout is None:
            raise ValueError('phase checkout required')
        raise SystemExit(0 if phase(args.checkout.resolve(), args.out.resolve()).get('passed') else 1)
    if args.frozen is None or args.mode is None:
        raise ValueError('frozen and mode required')
    raise SystemExit(0 if run(args.out, args.frozen, args.mode)['passed'] else 1)
