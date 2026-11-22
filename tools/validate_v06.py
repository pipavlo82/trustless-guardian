"""v0.6 bounded replay. Portable checks cannot establish model/OS execution."""
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


def run(out, runtime=None, portable=False):
    out=out.absolute();out.mkdir(parents=True,exist_ok=False);commands=[]
    write(out/'checkout.json',{'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip(),
        'status':subprocess.check_output(['git','status','--porcelain'],cwd=ROOT).decode(),
        'python':sys.version,'platform':platform.platform()})
    def execute(name,args):
        argv=[sys.executable,'-B',*args];start=time.perf_counter();p=subprocess.run(argv,cwd=ROOT,capture_output=True)
        (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
        commands.append({'name':name,'argv':argv,'exit_code':p.returncode,'seconds':time.perf_counter()-start})
        write(out/(name+'.command.json'),commands[-1]);print(json.dumps(commands[-1]),flush=True)
    execute('historical-portable',['tools/validate_v05.py','--portable','--out',str(out/'portable')])
    execute('frozen-baseline',['tools/v06_integrity.py'])
    determinism='NOT_COVERED';reports=[]
    if not portable:
        if runtime is None:raise ValueError('RUNTIME_REQUIRED')
        for mode,flags in [('normal',[]),('repeat',[]),('optimized',['-O'])]:
            execute(mode,[*flags,'demo/real-agent/run.py','--runtime',str(runtime.resolve()),'--out',str(out/mode)])
            p=out/mode/'report.json'
            reports.append(json.loads(p.read_bytes()) if p.exists() else None)
        if all(reports):
            raw=[json.dumps(r['checks'],sort_keys=True,separators=(',',':')).encode() for r in reports]
            determinism='VERIFIED' if len(set(raw))==1 else 'REFUTED'
            write(out/'semantic.json',{'checks':reports[0]['checks'],'sha256':hashlib.sha256(raw[0]).hexdigest()})
    sources={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
             for folder in ('guardian','demo','tools','tests') for p in sorted((ROOT/folder).rglob('*.py'))}
    report={'schema':'guardian.validation.v06','passed':all(c['exit_code']==0 for c in commands) and (portable or determinism=='VERIFIED'),
        'portable_only':portable,'commands':commands,'source_sha256':sources,'semantic_determinism':determinism,
        'real_agent_chain':'LABORATORY_VERIFIED' if not portable and all(r and r['passed'] for r in reports) else 'NOT_COVERED',
        'historical_full_regression':'RUN_SEPARATELY','mutations':'RUN_SEPARATELY','independent_machine':'NOT_COVERED'}
    write(out/'report.json',report);return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--runtime',type=Path);p.add_argument('--portable',action='store_true');a=p.parse_args()
    raise SystemExit(not run(a.out,a.runtime,a.portable)['passed'])
