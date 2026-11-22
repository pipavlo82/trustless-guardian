"""Current gates + unchanged frozen regression; no source/hash rewriting."""
from pathlib import Path
import argparse, json, os, subprocess, sys, time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.stack_integrity_v1 import verify,FROZEN

def execute(argv,cwd,out,name,timeout=7200):
    start=time.time()
    try:
        p=subprocess.run([str(x) for x in argv],cwd=cwd,capture_output=True,timeout=timeout)
        code=p.returncode; stdout=p.stdout;stderr=p.stderr
    except subprocess.TimeoutExpired as e:
        code=124;stdout=e.stdout or b'';stderr=(e.stderr or b'')+b'\nTIMEOUT_NOT_A_PASS\n'
    (out/(name+'.stdout')).write_bytes(stdout);(out/(name+'.stderr')).write_bytes(stderr)
    row={'argv':[str(x) for x in argv],'cwd':str(cwd),'exit_code':code,'started_unix':start,'seconds':time.time()-start}
    (out/(name+'.command.json')).write_text(json.dumps(row,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'name':name,'exit_code':code}),flush=True)
    return row

def run(out,pin,native=False):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    integrity=verify(ROOT,pin)
    (out/'integrity-before.json').write_text(json.dumps(integrity,sort_keys=True)+'\n',newline='\n')
    rows=[]
    for mode,flags in [('normal',[]),('repeat',[]),('optimized',['-O'])]:
        rows.append(execute([sys.executable,'-B',*flags,'-m','unittest','discover','-s','tests','-v'],ROOT,out,'current-'+mode))
    # Independent frozen checkout, verified before execution, not an inventory exemption.
    frozen=ROOT/'build'/('stack-frozen-'+str(time.time_ns()))
    rows.append(execute(['git','worktree','add','--detach',frozen,FROZEN],ROOT,out,'frozen-checkout'))
    if rows[-1]['exit_code']:return finish(out,rows,'HOLD')
    from tools.stack_integrity_v1 import tree,digest
    if any(not (frozen/n).is_file() or digest((frozen/n).read_bytes())!=h for n,h in tree(ROOT,FROZEN).items()):raise ValueError('FROZEN_BYTES_DIFFER')
    # Cache only a previously pinned official runtime; original prepare.py rechecks its SHA.
    cache=ROOT/'build/runtime/python-3.12.10-embed-amd64.zip'
    if cache.exists():
        target=frozen/'build/runtime'/cache.name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(cache.read_bytes())
    rows.append(execute([sys.executable,'-B',frozen/'tools/validate_v07.py','--portable','--out',out/'historical-portable'],frozen,out,'historical-portable'))
    if (ROOT/'research/gateway_abuse_replay_v0').exists():
        for mode,flags in [('normal',[]),('repeat',[]),('optimized',['-O'])]:
            rows.append(execute([sys.executable,'-B',*flags,'-m','research.gateway_abuse_replay_v0.cli','evaluate','--out',out/('holdout-'+mode+'.json')],ROOT,out,'holdout-'+mode))
            rows.append(execute([sys.executable,'-B',*flags,'-m','research.gateway_abuse_replay_v0.cli','mutations','--out',out/('mutations-'+mode+'.json')],ROOT,out,'mutations-'+mode))
    if native:
        if os.name!='nt':return finish(out,rows,'NOT_COVERED_WINDOWS')
        # Execute every original Windows v04 gate including historical physical mutations.
        # Updated launcher only changes child startup, not the validator or expected verdicts.
        rows.append(execute([sys.executable,'-B','tools/stack_windows_v1.py','--out',out/'windows','--frozen',frozen],ROOT,out,'windows',timeout=10800))
    after=verify(ROOT,pin)
    (out/'integrity-after.json').write_text(json.dumps(after,sort_keys=True)+'\n',newline='\n')
    return finish(out,rows,'PASS_LOCAL' if all(r['exit_code']==0 for r in rows) else 'HOLD')

def finish(out,rows,status):
    value={'status':status,'commands':rows,'production':'HOLD','external_review':'NOT_ESTABLISHED'}
    (out/'report.json').write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8',newline='\n');return value

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--pin',required=True);p.add_argument('--out',required=True,type=Path);p.add_argument('--native',action='store_true');a=p.parse_args()
    result=run(a.out,a.pin,a.native);raise SystemExit(0 if result['status']=='PASS_LOCAL' else 1)
