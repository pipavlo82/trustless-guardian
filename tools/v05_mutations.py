"""Separate v05 population: physical edits in disposable copies, actual OS witnesses."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
MUTANTS = {
    'resource_binding': ('guardian/policy.py', "if request['resource']!=policy['resource']:return deny('RESOURCE')", "if False:return deny('RESOURCE')", 'deny'),
    'policy_revocation': ('guardian/policy.py', "if request['actor']!=principal or principal not in policy['actors']:return deny('ACTOR')", "if False:return deny('ACTOR')", 'policy_change'),
    'post_write_outcome': ('guardian/hardened.py', "'execution':'RECOVERY_REQUIRED','failure_stage':stage", "'execution':'NOT_EXECUTED','failure_stage':stage", 'recovery'),
    'resource_acl': ('demo/run_demo.py', "lab.acl(lab.resource, broker='GRGW', agent='GRGX', other=None)  # V05 resource_acl", "lab.acl(lab.resource, broker='GRGW', agent='GRGW', other=None)  # V05 resource_acl", 'bypass'),
}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(json.dumps(value, sort_keys=True, indent=2).encode()+b'\n')


def classify(base, changed, restored, target, exact, applied):
    if not applied: return 'NOT_APPLIED'
    if not exact or not base or not restored or not base['laboratory_passed'] or not restored['laboratory_passed']: return 'CONTROL_BROKEN'
    if not changed: return 'CRASHED'
    checks = changed['checks']
    positive = ('allow_bytes', 'allow_outcome', 'allow_request', 'allow_ipc_identity', 'receipt_bindings', 'receipt_digest', 'bypass_positive')
    if not all(checks.get(k) for k in positive): return 'CONTROL_BROKEN'
    if checks.get(target): return 'SURVIVED'
    # A failed expectation or transport timeout alone is not a semantic kill.
    row = changed.get('target_observation', {})
    reply = row.get('response', {})
    before = row.get('before', {}).get('source', {}).get('hex')
    after = row.get('after', {}).get('source', {}).get('hex')
    if target in ('deny', 'policy_change'):
        expected = b'approved:unauthorized' if target == 'deny' else b'approved:revoked'
        distinguished = reply.get('status') == 'VERIFIED' and reply.get('execution') == 'COMMITTED' and after == expected.hex() and before != after
    elif target == 'recovery':
        distinguished = after == b'approved:ambiguous'.hex() and before != after and reply.get('execution') == 'NOT_EXECUTED'
    elif target == 'bypass':
        distinguished = before != after and any(r.get('operation') == 'write' and r.get('result') == 'SUCCEEDED' for r in row.get('attempts', []))
    else: distinguished = False
    return 'KILLED' if distinguished else 'CONTROL_BROKEN'


def run(out):
    out = out.absolute(); out.mkdir(parents=True, exist_ok=False); rows = []
    for name, (file, old, new, target) in MUTANTS.items():
        checkout = out/name/'checkout'; checkout.mkdir(parents=True)
        for folder in ('guardian', 'tools', 'demo'):
            shutil.copytree(ROOT/folder, checkout/folder, ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copyfile(ROOT/'runtime-lock.json', checkout/'runtime-lock.json')
        (checkout/'build/runtime').mkdir(parents=True)
        shutil.copyfile(ROOT/'build/runtime/python-3.12.10-embed-amd64.zip', checkout/'build/runtime/python-3.12.10-embed-amd64.zip')
        def execute(phase):
            path = out/name/phase
            argv = [sys.executable, '-B', *(['-O'] if sys.flags.optimize else []), str(checkout/'demo/run_demo.py'), '--controls-only', '--out', str(path)]
            start = time.perf_counter()
            try:
                p = subprocess.run(argv, capture_output=True, timeout=160); code = p.returncode; stdout = p.stdout; stderr = p.stderr
            except subprocess.TimeoutExpired as exc:
                code = None; stdout = exc.stdout or b''; stderr = exc.stderr or b''
            path.mkdir(parents=True, exist_ok=True); (path/'stdout.log').write_bytes(stdout); (path/'stderr.log').write_bytes(stderr)
            write(path/'command.json', {'argv': argv, 'exit_code': code, 'seconds': time.perf_counter()-start})
            result = path/'verification.json'
            if not result.exists() or code not in (0, 1): return None
            value = json.loads(result.read_bytes())
            observations = path/'observations.json'
            if observations.exists():
                key = {'deny':'DENY', 'policy_change':'POLICY_CHANGE', 'recovery':'RECOVERY', 'bypass':'BYPASS'}[target]
                value['target_observation'] = json.loads(observations.read_bytes())['controls'][key]
            return value
        source = checkout/file; original = source.read_bytes(); base = execute('original')
        applied = original.decode().count(old) == 1; modified = None; changed = None
        try:
            if applied:
                modified = original.decode().replace(old, new).encode(); source.write_bytes(modified); changed = execute('mutated')
        finally: source.write_bytes(original)
        restored = execute('restored'); exact = source.read_bytes() == original
        row = {'id': name, 'source': file, 'target': target, 'applied': applied, 'restored_byte_exact': exact,
               'original_sha256': hashlib.sha256(original).hexdigest(), 'mutated_sha256': hashlib.sha256(modified).hexdigest() if modified else None,
               'classification': classify(base, changed, restored, target, exact, applied)}
        rows.append(row); print(json.dumps(row), flush=True)
    counts = {key: sum(r['classification'] == key for r in rows) for key in ('KILLED', 'SURVIVED', 'CRASHED', 'NOT_APPLIED', 'CONTROL_BROKEN')}
    result = {'schema': 'guardian.mutations.v05', 'mutants': rows, 'counts': counts,
              'passed': counts['KILLED'] == len(MUTANTS), 'real_agent_mutations': 'NOT_COVERED', 'historical_populations_unchanged': True}
    write(out/'report.json', result); return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--out', type=Path, required=True); a = p.parse_args()
    raise SystemExit(not run(a.out)['passed'])
