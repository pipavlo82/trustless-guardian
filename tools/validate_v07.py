"""Separate live-model and deterministic OS populations; all requested failures persist."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def write(p, value): p.write_bytes(json.dumps(value, sort_keys=True, indent=2).encode()+b'\n')


def run(out, runtime=None, portable=False, offline=False, no_mutations=False):
    out = out.absolute(); out.mkdir(parents=True, exist_ok=False); commands = []
    write(out/'checkout.json', {'head': subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT).decode().strip(),
          'status': subprocess.check_output(['git','status','--porcelain'], cwd=ROOT).decode(),
          'python': sys.version, 'platform': platform.platform()})
    def execute(name, args):
        argv = [sys.executable, '-B', *args]; start = time.perf_counter()
        p = subprocess.run(argv, cwd=ROOT, capture_output=True)
        (out/(name+'.stdout')).write_bytes(p.stdout); (out/(name+'.stderr')).write_bytes(p.stderr)
        row = {'name': name, 'argv': argv, 'exit_code': p.returncode, 'seconds': time.perf_counter()-start}
        commands.append(row); write(out/(name+'.command.json'), row); print(json.dumps(row), flush=True)
    execute('historical-portable', ['tools/validate_v06.py', '--portable', '--out', str(out/'portable')])
    execute('frozen-baseline', ['tools/v07_integrity.py'])
    deterministic = {}; populations = {}; mutations = {}
    if not portable:
        execute('prepare', ['tools/prepare.py'])
        for population in (['deterministic'] if offline else ['deterministic', 'live']):
            if population == 'live' and runtime is None: raise ValueError('LIVE_RUNTIME_REQUIRED')
            reports = []
            for mode, flags in [('normal', []), ('repeat', []), ('optimized', ['-O'])]:
                name = population+'-'+mode
                execute(name, [*flags, 'demo/developer-preview/run.py', '--mode', population, '--out', str(out/name)] +
                        (['--runtime', str(runtime.resolve())] if population == 'live' else []))
                path = out/name/'report.json'; reports.append(json.loads(path.read_bytes()) if path.exists() else None)
            populations[population] = reports
            semantic = [json.dumps(r['checks'], sort_keys=True, separators=(',', ':')).encode() for r in reports if r]
            deterministic[population] = len(semantic) == 3 and len(set(semantic)) == 1 and all(r['passed'] for r in reports)
            write(out/(population+'-semantic.json'), {'byte_identical': deterministic[population],
                  'sha256': [hashlib.sha256(raw).hexdigest() for raw in semantic]})
        if not no_mutations:
            for mode, flags in [('normal', []), ('repeat', []), ('optimized', ['-O'])]:
                name = 'deterministic-mutations-'+mode
                execute(name, [*flags, 'demo/developer-preview/mutations.py', '--out', str(out/name)])
                path = out/name/'report.json'; mutations[mode] = json.loads(path.read_bytes())['counts'] if path.exists() else {'NOT_COVERED': 4}
    report = {'schema': 'guardian.validation.v07', 'passed': all(c['exit_code'] == 0 for c in commands) and all(deterministic.values()),
              'portable_only': portable, 'offline_only': offline, 'commands': commands,
              'semantic_determinism': deterministic, 'populations': populations, 'deterministic_mutations': mutations,
              'historical_live_mutation_population': 'IMMUTABLE_V06_2_KILLED_2_CONTROL_BROKEN',
              'historical_conformance': 'RUN_SEPARATELY', 'cross_machine': 'NOT_COVERED', 'production_ready': False}
    write(out/'report.json', report); return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--out', type=Path, required=True); p.add_argument('--runtime', type=Path)
    p.add_argument('--portable', action='store_true'); p.add_argument('--offline', action='store_true'); p.add_argument('--no-mutations', action='store_true')
    a = p.parse_args(); raise SystemExit(not run(a.out, a.runtime, a.portable, a.offline, a.no_mutations)['passed'])
