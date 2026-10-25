"""v02 replay with raw process logs; unavailable OS evidence never counts as PASS."""
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
        start=time.perf_counter();p=subprocess.run([sys.executable,'-B',*args],cwd=ROOT,capture_output=True)
        (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
        row={'name':name,'argv':[sys.executable,'-B',*args],'exit_code':p.returncode,'seconds':time.perf_counter()-start}
        commands.append(row);write(out/(name+'.command.json'),row);print(json.dumps(row),flush=True)
    # Original suite, archive verification and integrity are mandatory regression gates.
    execute('v0-regression',['tools/validate.py','--out',str(out/'v0')]+(['--portable'] if portable else [])+(['--no-mutations'] if no_mutations else []))
    deterministic='NOT_COVERED';counts={}
    if not portable:
        for mode,flags in [('normal',[]),('repeat',[]),('optimized',['-O'])]:
            execute('v02-'+mode,[*flags,'tools/v02_campaign.py','--out',str(out/mode)])
        paths=[out/m/'semantic.json' for m in ('normal','repeat','optimized')]
        if all(p.is_file() for p in paths):deterministic='VERIFIED' if len({p.read_bytes() for p in paths})==1 else 'REFUTED'
        if not no_mutations:
            execute('v02-mutations',[*(['-O'] if sys.flags.optimize else []),'tools/v02_mutations.py','--out',str(out/'mutations')])
            if (out/'mutations/report.json').exists():counts=json.loads((out/'mutations/report.json').read_bytes())['counts']
    source={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in ('guardian','tools','tests') for p in sorted((ROOT/folder).rglob('*.py')) if '__pycache__' not in p.parts}
    report={'schema':'guardian.validation.v02','passed':all(r['exit_code']==0 for r in commands) and (portable or deterministic=='VERIFIED'),
      'portable_only':portable,'os_enforcement':'NOT_COVERED' if portable else 'see campaign witnesses',
      'commands':commands,'python':sys.version,'platform':platform.platform(),'source_sha256':source,
      'semantic_determinism':deterministic,'mutations':counts,'external_execution':'UNVERIFIABLE','production_ready':False}
    write(out/'report.json',report);return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--portable',action='store_true');p.add_argument('--no-mutations',action='store_true');a=p.parse_args()
    raise SystemExit(not run(a.out,a.portable,a.no_mutations)['passed'])
