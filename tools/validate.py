"""Record raw subprocess evidence. Every requested failed/unavailable run fails validation."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(json.dumps(value,sort_keys=True,indent=2).encode()+b'\n')


def run(out,portable=False,mutations=True):
    out=out.absolute()
    if out.exists():raise ValueError('use a fresh output directory; evidence is not overwritten')
    out.mkdir(parents=True);commands=[]
    def execute(name,args):
        start=time.perf_counter();p=subprocess.run(args,cwd=ROOT,capture_output=True)
        (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
        row={'name':name,'argv':args,'exit_code':p.returncode,'seconds':time.perf_counter()-start}
        commands.append(row);write(out/(name+'.command.json'),row)
        print(json.dumps(row),flush=True)
        return p.returncode
    for mode,flags in [('normal',[]),('repeat',[]),('optimized',['-O'])]:
        execute('unit-'+mode,[sys.executable,'-B',*flags,'-m','unittest','discover','-s','tests','-v'])
    determinism='NOT_COVERED';mutation_counts={};enforcement='NOT_COVERED'
    if not portable:
        execute('runtime',[sys.executable,'-B','tools/prepare.py'])
        for mode,flags in [('normal',[]),('repeat',[]),('optimized',['-O'])]:
            execute('lab-'+mode,[sys.executable,'-B',*flags,'tools/lab.py','--out',str(out/('lab-'+mode))])
        execute('ownership',[sys.executable,'-B','tools/ownership_control.py','--out',str(out/'ownership')])
        paths=[out/('lab-'+m)/'semantic.json' for m in ('normal','repeat','optimized')]
        if all(p.exists() for p in paths):
            determinism='VERIFIED' if len({p.read_bytes() for p in paths})==1 else 'REFUTED'
        if all((out/('lab-'+m)/'summary.json').exists() and json.loads((out/('lab-'+m)/'summary.json').read_bytes())['passed'] for m in ('normal','repeat','optimized')):
            enforcement='LABORATORY_VERIFIED'
        if mutations:
            execute('mutations',[sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),'tools/mutations.py','--out',str(out/'mutations')])
            path=out/'mutations/report.json'
            if path.exists():mutation_counts=json.loads(path.read_bytes())['counts']
    for archive in sorted((ROOT/'evidence').glob('*.zip')):
        execute('evidence-'+archive.stem,[sys.executable,'-B','tools/evidence.py','verify',str(archive)])
    if (ROOT/'artifacts.sha256.json').exists():execute('integrity',[sys.executable,'-B','tools/integrity.py'])
    source={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
      for directory in ('guardian','tools','tests') for p in sorted((ROOT/directory).rglob('*.py')) if '__pycache__' not in p.parts}
    passed=all(r['exit_code']==0 for r in commands) and (portable or (determinism=='VERIFIED' and enforcement=='LABORATORY_VERIFIED'))
    report={'schema':'guardian.validation.v0','passed':passed,'portable_only':portable,'commands':commands,
      'python':sys.version,'platform':platform.platform(),'source_sha256':source,'mutation_counts':mutation_counts,
      'semantic_determinism':determinism,'os_enforcement':enforcement,'production_ready':False,'external_execution':'UNVERIFIABLE'}
    write(out/'report.json',report);print(json.dumps({'passed':passed,'determinism':determinism,'enforcement':enforcement,'mutations':mutation_counts}))
    return passed


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--portable',action='store_true');p.add_argument('--no-mutations',action='store_true');a=p.parse_args()
    raise SystemExit(not run(a.out,a.portable,not a.no_mutations))
