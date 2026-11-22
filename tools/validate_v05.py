"""Bounded v05 replay. Portable success never promotes real-agent coverage."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def write(path, value): path.write_bytes(json.dumps(value, sort_keys=True, indent=2).encode()+b'\n')


def run(out, portable=False, no_mutations=False):
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
    execute('portable-regression', ['tools/validate_v04.py', '--portable', '--out', str(out/'portable')])
    determinism = 'NOT_COVERED'; mutations = {}
    if not portable:
        execute('prepare', ['tools/prepare.py'])
        for mode, flags in [('normal', []), ('repeat', []), ('optimized', ['-O'])]:
            execute(mode, [*flags, 'demo/run_demo.py', '--out', str(out/mode)])
            if not no_mutations:
                execute('mutations-'+mode, [*flags, 'tools/v05_mutations.py', '--out', str(out/('mutations-'+mode))])
                path = out/('mutations-'+mode)/'report.json'
                if path.exists(): mutations[mode] = json.loads(path.read_bytes())['counts']
        files = [out/m/'semantic.json' for m in ('normal', 'repeat', 'optimized')]
        if all(p.exists() for p in files): determinism = 'VERIFIED' if len({p.read_bytes() for p in files}) == 1 else 'REFUTED'
    sources = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
               for folder in ('guardian','tools','tests','demo') for p in sorted((ROOT/folder).rglob('*.py'))}
    result = {'schema': 'guardian.validation.v05', 'laboratory_passed': all(r['exit_code']==0 for r in commands) and (portable or determinism=='VERIFIED'),
              'portable_only': portable, 'real_agent_status': 'NOT_COVERED', 'commands': commands, 'mutations': mutations,
              'semantic_determinism': determinism, 'source_sha256': sources,
              'historical_full_suite': 'RUN_SEPARATELY_WITH_VALIDATE_V04', 'second_windows_machine': 'NOT_COVERED'}
    write(out/'report.json', result); return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--out', type=Path, required=True)
    p.add_argument('--portable', action='store_true'); p.add_argument('--no-mutations', action='store_true'); a = p.parse_args()
    raise SystemExit(not run(a.out, a.portable, a.no_mutations)['laboratory_passed'])
