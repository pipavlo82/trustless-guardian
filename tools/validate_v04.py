"""Versioned v04 runner; no unavailable enforcement becomes portable success."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
def write(path,value):path.write_bytes(json.dumps(value,sort_keys=True,indent=2).encode()+b'\n')
def run(out,portable=False,no_mutations=False):
    out=out.absolute();out.mkdir(parents=True,exist_ok=False);commands=[]
    write(out/'checkout.json',{'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip(),
        'status':subprocess.check_output(['git','status','--porcelain'],cwd=ROOT).decode(),'python':sys.version,'platform':platform.platform()})
    def execute(name,args):
        argv=[sys.executable,'-B',*args];start=time.perf_counter();p=subprocess.run(argv,cwd=ROOT,capture_output=True)
        (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
        row={'argv':argv,'exit_code':p.returncode,'seconds':time.perf_counter()-start,'name':name};commands.append(row);write(out/(name+'.command.json'),row);print(json.dumps(row),flush=True)
    execute('v03-regression',['tools/validate_v03.py','--out',str(out/'v03')]+(['--portable'] if portable else [])+(['--no-mutations'] if no_mutations else []))
    determinism='NOT_COVERED';mutations={}
    if not portable:
        for mode,flags in [('normal',[]),('repeat',[]),('optimized',['-O'])]:execute(mode,[*flags,'tools/v04_campaign.py','--out',str(out/mode)])
        paths=[out/m/'semantic.json' for m in ('normal','repeat','optimized')]
        if all(p.exists() for p in paths):determinism='VERIFIED' if len({p.read_bytes() for p in paths})==1 else 'REFUTED'
        if not no_mutations:
            # Historical populations keep their own reports. Normal is already
            # executed by the versioned regression runner above.
            for version,tool in [('v0','mutations.py'),('v02','v02_mutations.py'),('v03','v03_mutations.py')]:
                for mode,flags in [('repeat',[]),('optimized',['-O'])]:
                    execute(version+'-mutations-'+mode,[*flags,'tools/'+tool,'--out',str(out/(version+'-mutations-'+mode))])
            for mode,flags in [('normal',[]),('repeat',[]),('optimized',['-O'])]:
                execute('mutations-'+mode,[*flags,'tools/v04_mutations.py','--out',str(out/('mutations-'+mode))])
                p=out/('mutations-'+mode)/'report.json'
                if p.exists():mutations[mode]=json.loads(p.read_bytes())['counts']
    sources={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for folder in ('guardian','tools','tests') for p in sorted((ROOT/folder).rglob('*.py'))}
    report={'schema':'guardian.validation.v04','passed':all(r['exit_code']==0 for r in commands) and (portable or determinism=='VERIFIED'),
        'commands':commands,'portable_only':portable,'semantic_determinism':determinism,'mutations':mutations,'source_sha256':sources,
        'external_reviewer':'NOT_COVERED','second_windows_machine':'NOT_COVERED','production_ready':False}
    write(out/'report.json',report);return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--portable',action='store_true');p.add_argument('--no-mutations',action='store_true');a=p.parse_args();raise SystemExit(not run(a.out,a.portable,a.no_mutations)['passed'])
