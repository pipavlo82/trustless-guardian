"""Bounded v03 evidence runner; preserved v0/v02 controls remain separate."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.validate import write


def run(out,portable=False,no_mutations=False):
    out=out.absolute()
    if out.exists():raise ValueError('fresh output directory required')
    out.mkdir(parents=True);commands=[]
    def execute(name,args):
        argv=[sys.executable,'-B',*args];start=time.perf_counter();p=subprocess.run(argv,cwd=ROOT,capture_output=True)
        (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
        row={'argv':argv,'exit_code':p.returncode,'seconds':time.perf_counter()-start,'name':name};commands.append(row);write(out/(name+'.command.json'),row);print(json.dumps(row),flush=True)
    write(out/'checkout.json',{'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip(),
      'status':subprocess.check_output(['git','status','--porcelain'],cwd=ROOT).decode(),'python':sys.version,'platform':platform.platform()})
    execute('v02-regression',['tools/validate_v02.py','--out',str(out/'v02')]+(['--portable'] if portable else [])+(['--no-mutations'] if no_mutations else []))
    deterministic='NOT_COVERED';counts={}
    if not portable:
        execute('runner-token',['tools/ci_diagnostics.py','--out',str(out/'runner-token.json')])
        execute('harness-crash-control',['tools/v03_harness_control.py','--out',str(out/'harness-crash-control')])
        for mode,flags in [('normal',[]),('repeat',[]),('optimized',['-O'])]:
            execute(mode,[*flags,'tools/v03_campaign.py','--out',str(out/mode)])
        paths=[out/m/'semantic.json' for m in ('normal','repeat','optimized')]
        if all(p.exists() for p in paths):deterministic='VERIFIED' if len({p.read_bytes() for p in paths})==1 else 'REFUTED'
        if not no_mutations:
            for mode,flags in [('normal',[]),('optimized',['-O'])]:
                execute('mutations-'+mode,[*flags,'tools/v03_mutations.py','--out',str(out/('mutations-'+mode))])
                p=out/('mutations-'+mode)/'report.json'
                if p.exists():counts[mode]=json.loads(p.read_bytes())['counts']
    sources={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for folder in ('guardian','tools','tests') for p in sorted((ROOT/folder).rglob('*.py'))}
    report={'schema':'guardian.validation.v03','passed':all(r['exit_code']==0 for r in commands) and (portable or deterministic=='VERIFIED'),
      'commands':commands,'portable_only':portable,'semantic_determinism':deterministic,'mutations':counts,'source_sha256':sources,
      'external_reviewer':'NOT_COVERED','second_windows_machine':'NOT_COVERED','production_ready':False}
    write(out/'report.json',report);return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--portable',action='store_true');p.add_argument('--no-mutations',action='store_true');a=p.parse_args()
    raise SystemExit(not run(a.out,a.portable,a.no_mutations)['passed'])
