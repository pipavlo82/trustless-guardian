"""Targeted real-Windows witnesses for the PR3 native transition.

The security sources come from a clean frozen checkout.  Only disposable test
harness timing/publication code is overlaid; every physical guard mutation is
then applied once and restored byte-for-byte.
"""
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
FROZEN = '03f6ffc6f4b983cfcc39f401f47165021e67e673'

CASES = {
    'v04_runtime_after_commit': {
        'generation': 'v04', 'witness': 'runtime_after_commit', 'scenario': True,
    },
    'v03_committed_failure': {
        'generation': 'v03', 'witness': 'committed_failure', 'scenario': True,
    },
    'v04_ordinary_exception_legacy': {
        'generation': 'v04', 'witness': 'runtime_after_write',
        'legacy': True, 'source': 'guardian/hardened.py',
        'old': 'except Exception:  # V04 ordinary_exception_boundary',
        'new': "except (OSError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,RecursionError,__import__('sqlite3').Error):  # V04 ordinary_exception_boundary",
    },
    'v04_recovery_response': {
        'generation': 'v04', 'witness': 'crash_written',
        'source': 'guardian/hardened.py',
        'old': "'execution':'RECOVERY_REQUIRED','retry_permitted':False}  # V02 recovery_gate",
        'new': "'execution':'NOT_EXECUTED','retry_permitted':False}  # V02 recovery_gate",
    },
    'v04_dispatch_outcome': {
        'generation': 'v04', 'witness': 'dispatch_return_failure',
        'source': 'guardian/dispatch.py',
        'old': "'reason':'DISPATCH_OUTCOME_UNCERTAIN','execution':'RECOVERY_REQUIRED'",
        'new': "'reason':'DISPATCH_OUTCOME_UNCERTAIN','execution':'NOT_EXECUTED'",
    },
    'v04_readback_consistency': {
        'generation': 'v04', 'witness': 'readback_mismatch',
        'source': 'guardian/hardened.py',
        'old': "if after!=intended:raise OSError('READBACK_MISMATCH')",
        'new': "if False:raise OSError('READBACK_MISMATCH')",
    },
    'v03_same_bytes': {
        'generation': 'v03', 'witness': 'same_bytes',
        'source': 'guardian/recovery.py',
        'old': "if i['before_sha256']==i['after_sha256']:state='RECOVERY_REQUIRED'  # V03 same_bytes",
        'new': "if False:state='RECOVERY_REQUIRED'  # V03 same_bytes",
    },
    'v02_resource_identity': {
        'generation': 'v02', 'witness': 'resource_identity',
        'source': 'guardian/hardened.py',
        'old': "if pf.identity!=cfg['policy_identity'] or rf.identity!=cfg['resource_identity']:return refusal('RESOURCE_IDENTITY')  # V02 resource_identity",
        'new': "if False:return refusal('RESOURCE_IDENTITY')  # V02 resource_identity",
    },
    'v02_directory_identity': {
        'generation': 'v02', 'witness': 'directory_identity',
        'source': 'guardian/hardened.py',
        'old': "if identity is not None and self.identity!=identity:raise ValueError('DIRECTORY_IDENTITY')  # V02 directory_identity",
        'new': "if False:raise ValueError('DIRECTORY_IDENTITY')  # V02 directory_identity",
    },
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n',
                    encoding='utf-8', newline='\n')


def replace_once(path, old, new):
    raw = path.read_bytes(); text = raw.decode('utf-8')
    if text.count(old) != 1:
        raise ValueError('OVERLAY_TARGET_NOT_UNIQUE: '+path.as_posix())
    changed = text.replace(old, new).encode('utf-8')
    path.write_bytes(changed)
    return {'path': '/'.join(path.parts[-2:]), 'before_sha256': sha(raw),
            'after_sha256': sha(changed)}


def apply_harness_overlay(checkout):
    """Bound the lab generously and consume ready.json only after valid JSON."""
    rows = []
    lab = checkout/'tools/v02_lab.py'
    rows.append(replace_once(
        lab,
        "        result=container.launch([self.runtime/'python.exe','-B',*(['-O'] if sys.flags.optimize else []),self.runtime/'v02_worker.py',p],self.runtime,15)",
        "        result=container.launch([self.runtime/'python.exe','-B',*(['-O'] if sys.flags.optimize else []),self.runtime/'v02_worker.py',p],self.runtime,45)",
    ))
    rows.append(replace_once(
        lab,
        "        deadline=time.monotonic()+5\n        while time.monotonic()<deadline and self.thread.is_alive():\n            if (self.journal/'ready.json').exists():break\n            time.sleep(.01)\n        if not (self.journal/'ready.json').exists():self.finish(name);raise RuntimeError('BROKER_START_FAILED')\n        self.pid=json.loads((self.journal/'ready.json').read_bytes())['pid']",
        "        deadline=time.monotonic()+20;ready=None\n        while time.monotonic()<deadline and self.thread.is_alive():\n            try:ready=json.loads((self.journal/'ready.json').read_bytes());break\n            except (FileNotFoundError,json.JSONDecodeError):time.sleep(.01)\n        if ready is None:self.finish(name);raise RuntimeError('BROKER_START_FAILED')\n        self.pid=ready['pid']",
    ))
    rows.append(replace_once(lab, '        if self.thread:self.thread.join(18)',
                             '        if self.thread:self.thread.join(45)'))

    worker02 = checkout/'tools/v02_worker.py'
    rows.append(replace_once(
        worker02,
        "                ipc.io(pipe.handle,'connect',timeout_ms=cfg.get('timeout_ms',1800));connected=True\n                raw=ipc.io(pipe.handle,'read',timeout_ms=cfg.get('timeout_ms',1800))",
        "                ipc.io(pipe.handle,'connect',timeout_ms=cfg.get('timeout_ms',15000));connected=True\n                raw=ipc.io(pipe.handle,'read',timeout_ms=cfg.get('timeout_ms',15000))",
    ))
    rows.append(replace_once(
        worker02,
        "                    ipc.io(pipe.handle,'write',canonical(response),timeout_ms=700)\n                    ipc.io(pipe.handle,'read',timeout_ms=700)",
        "                    ipc.io(pipe.handle,'write',canonical(response),timeout_ms=15000)\n                    ipc.io(pipe.handle,'read',timeout_ms=15000)",
    ))
    rows.append(replace_once(
        worker02,
        "            result['response']=ipc.exchange(cfg['pipe'],cfg['server_pid'],bytes.fromhex(cfg['raw_hex']))",
        "            h=ipc.connect(cfg['pipe'],cfg['server_pid'])\n            try:\n                ipc.io(h,'write',bytes.fromhex(cfg['raw_hex']),timeout_ms=15000)\n                result['response']=ipc.parse(ipc.io(h,'read',timeout_ms=15000))\n                ipc.io(h,'write',b'ACK',timeout_ms=15000)\n            finally:win.close(h)",
    ))

    campaign03 = checkout/'tools/v03_campaign.py'
    rows.append(replace_once(
        campaign03,
        "        result=container.launch([self.runtime/'python.exe','-B',*(['-O'] if sys.flags.optimize else []),self.runtime/'v03_worker.py',p],self.runtime,20)",
        "        result=container.launch([self.runtime/'python.exe','-B',*(['-O'] if sys.flags.optimize else []),self.runtime/'v03_worker.py',p],self.runtime,45)",
    ))
    rows.append(replace_once(campaign03, '    until=time.monotonic()+6',
                             '    until=time.monotonic()+20'))

    worker03 = checkout/'tools/v03_worker.py'
    rows.append(replace_once(
        worker03,
        "                ipc.io(pipe.handle,'connect',timeout_ms=cfg.get('timeout_ms',1800));connected=True\n                raw=ipc.io(pipe.handle,'read',timeout_ms=cfg.get('timeout_ms',1800))",
        "                ipc.io(pipe.handle,'connect',timeout_ms=cfg.get('timeout_ms',15000));connected=True\n                raw=ipc.io(pipe.handle,'read',timeout_ms=cfg.get('timeout_ms',15000))",
    ))
    rows.append(replace_once(
        worker03,
        "                    ipc.io(pipe.handle,'write',canonical(response),timeout_ms=700)\n                    ipc.io(pipe.handle,'read',timeout_ms=700)",
        "                    ipc.io(pipe.handle,'write',canonical(response),timeout_ms=15000)\n                    ipc.io(pipe.handle,'read',timeout_ms=15000)",
    ))
    rows.append(replace_once(
        worker03,
        "            ipc.io(h,'write',raw[:len(raw)//2]);ipc.io(h,'write',raw[len(raw)//2:])",
        "            ipc.io(h,'write',raw[:len(raw)//2],timeout_ms=15000);ipc.io(h,'write',raw[len(raw)//2:],timeout_ms=15000)",
    ))
    rows.append(replace_once(worker03, "        else:ipc.io(h,'write',raw)",
                             "        else:ipc.io(h,'write',raw,timeout_ms=15000)"))
    rows.append(replace_once(
        worker03,
        "            result['response']=parse(ipc.io(h,'read'));ipc.io(h,'write',b'ACK')",
        "            result['response']=parse(ipc.io(h,'read',timeout_ms=15000));ipc.io(h,'write',b'ACK',timeout_ms=15000)",
    ))

    campaign04 = checkout/'tools/v04_campaign.py'
    rows.append(replace_once(
        campaign04,
        "        result=container.launch([self.runtime/'python.exe','-B',*(['-O'] if sys.flags.optimize else []),self.runtime/'v04_worker.py',path],self.runtime,20)",
        "        result=container.launch([self.runtime/'python.exe','-B',*(['-O'] if sys.flags.optimize else []),self.runtime/'v04_worker.py',path],self.runtime,45)",
    ))
    return rows


def phase(checkout, out, case_id):
    case = CASES[case_id]
    sys.path.insert(0, str(checkout))
    if case['generation'] == 'v04':
        from tools import v04_campaign as campaign
        return campaign.witness(case['witness'], out, case.get('legacy', False))
    if case['generation'] == 'v03':
        from tools import v03_campaign as campaign
        return campaign.witness(case['witness'], out)
    from tools import v02_campaign as campaign
    return campaign.witness(case['witness'], out)


def execute_phase(checkout, out, case_id, mode, name):
    flags = ['-O'] if mode == 'optimized' else []
    argv = [sys.executable, '-B', *flags, Path(__file__).resolve(), '--phase',
            '--checkout', checkout, '--out', out, '--case', case_id]
    started = time.time()
    try:
        run = subprocess.run([str(x) for x in argv], cwd=ROOT,
                             capture_output=True, timeout=300)
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


def classify(case, baseline, mutated, restored, exact):
    generation = case['generation']
    if generation == 'v04':
        def valid(value):
            if not value or value.get('control_broken'):
                return False
            checks = value.get('checks', {})
            return all(checks.get(key) for key in (
                'positive', 'controlled_process', 'host_digest',
                'independent_host_bytes', 'independent_broker_token'))
        if not exact or not all(valid(x) and x.get('passed') for x in (baseline, restored)):
            return 'CONTROL_BROKEN'
        if mutated is None:
            return 'CRASHED'
        if not valid(mutated):
            return 'CONTROL_BROKEN'
        return 'SURVIVED' if mutated.get('passed') else 'KILLED'
    if generation == 'v03':
        if (not exact or not baseline or not restored
                or not all(x.get('positive_ok') and x.get('negative_ok')
                           for x in (baseline, restored))):
            return 'CONTROL_BROKEN'
        if mutated is None:
            return 'CRASHED'
        if not mutated.get('positive_ok'):
            return 'CONTROL_BROKEN'
        return 'SURVIVED' if mutated.get('negative_ok') else 'KILLED'
    def sound(value):
        return value is not None and value.get('positive_ok') and not value.get('negative_wrote')
    if not sound(baseline) or not sound(restored) or not exact:
        return 'CONTROL_BROKEN'
    if mutated is None:
        return 'CRASHED'
    if not mutated.get('positive_ok'):
        return 'CONTROL_BROKEN'
    return 'KILLED' if mutated.get('negative_wrote') else 'SURVIVED'


def run(out, frozen, case_id, mode):
    out = out.resolve(); frozen = frozen.resolve(); case = CASES[case_id]
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

    temp_root = Path(tempfile.mkdtemp(prefix='guardian-pr3-'))
    checkout = temp_root/'checkout'
    try:
        for folder in ('guardian', 'tools'):
            shutil.copytree(frozen/folder, checkout/folder,
                            ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copyfile(frozen/'runtime-lock.json', checkout/'runtime-lock.json')
        target_runtime = checkout/'build/runtime'/runtime.name
        target_runtime.parent.mkdir(parents=True)
        shutil.copyfile(runtime, target_runtime)
        overlay = apply_harness_overlay(checkout)
        save(out/'harness-overlay.json', {
            'classification': 'DISPOSABLE_TEST_HARNESS_ONLY',
            'security_sources_changed': False, 'files': overlay,
        })

        if case.get('scenario'):
            current = execute_phase(checkout, out/'current', case_id, mode, 'current')
            if case['generation'] == 'v04':
                passed = bool(current and current.get('passed') is True
                              and not current.get('control_broken'))
            else:
                passed = bool(current and current.get('positive_ok')
                              and current.get('negative_ok'))
            report = {
                'schema': 'guardian.pr3-native-witness.v1', 'case': case_id,
                'kind': 'SCENARIO', 'mode': mode, 'passed': passed,
                'frozen_sha': head, 'witness': current,
                'harness_overlay_sha256': sha((out/'harness-overlay.json').read_bytes()),
                'historical_raw_result': 'PRESERVED_SEPARATELY',
                'production': 'HOLD', 'external_review': 'NOT_ESTABLISHED',
            }
            save(out/'report.json', report); return report

        source = checkout/case['source']; original = source.read_bytes()
        text = original.decode('utf-8')
        if text.count(case['old']) != 1:
            raise ValueError('MUTATION_TARGET_NOT_UNIQUE')
        changed = text.replace(case['old'], case['new']).encode('utf-8')
        baseline = execute_phase(checkout, out/'baseline', case_id, mode, 'baseline')
        source.write_bytes(changed)
        mutated = execute_phase(checkout, out/'mutated', case_id, mode, 'mutated')
        source.write_bytes(original)
        restored = execute_phase(checkout, out/'restored', case_id, mode, 'restored')
        exact = source.read_bytes() == original
        classification = classify(case, baseline, mutated, restored, exact)
        passed = classification == 'KILLED'
        report = {
            'schema': 'guardian.pr3-native-witness.v1', 'case': case_id,
            'kind': 'PHYSICAL_MUTATION', 'generation': case['generation'],
            'mode': mode, 'passed': passed, 'classification': classification,
            'frozen_sha': head, 'source': case['source'],
            'original_sha256': sha(original), 'mutated_sha256': sha(changed),
            'physical_mutation_applied': True, 'source_restored': exact,
            'phases': {'baseline': baseline, 'mutated': mutated, 'restored': restored},
            'harness_overlay_sha256': sha((out/'harness-overlay.json').read_bytes()),
            'historical_raw_result': 'PRESERVED_SEPARATELY',
            'production': 'HOLD', 'external_review': 'NOT_ESTABLISHED',
        }
        save(out/'report.json', report); return report
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--frozen', type=Path)
    parser.add_argument('--case', choices=tuple(CASES), required=True)
    parser.add_argument('--mode', choices=('normal', 'repeat', 'optimized'), default='normal')
    parser.add_argument('--phase', action='store_true')
    parser.add_argument('--checkout', type=Path)
    args = parser.parse_args()
    if args.phase:
        if args.checkout is None:
            raise ValueError('phase checkout required')
        value = phase(args.checkout.resolve(), args.out.resolve(), args.case)
        if CASES[args.case].get('scenario'):
            ok = (value.get('passed') is True if CASES[args.case]['generation'] == 'v04'
                  else value.get('positive_ok') and value.get('negative_ok'))
        else:
            ok = True
        raise SystemExit(0 if ok else 1)
    if args.frozen is None:
        raise ValueError('frozen required')
    raise SystemExit(0 if run(args.out, args.frozen, args.case, args.mode)['passed'] else 1)
