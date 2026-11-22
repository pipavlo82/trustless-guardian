"""Use pinned two-stage reduction on elevated runners; verify ordinary child identity."""
from pathlib import Path
import argparse, ctypes as c, json, os, subprocess, sys
from ctypes import wintypes as w
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))

def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')

def permitted(token):
    return (not token['elevated'] and not token['administrators_enabled']
            and token['integrity_sid']=='S-1-16-8192' and not token['appcontainer']
            and token['capability_count']==0
            and all(not v['enabled'] or n=='SeChangeNotifyPrivilege' for n,v in token['privilege_attributes'].items()))

def current():
    from guardian import windows as win
    from tools.ci_tokens import inspect
    h=w.HANDLE();win.check(win.open_token(win.current(),8,c.byref(h)))
    try:return inspect(h)
    finally:win.close(h)

def child(out,frozen,smoke):
    from tools.stack_integrity_v1 import FROZEN,tree,digest
    observed=current()
    if not permitted(observed):raise ValueError('CHILD_TOKEN_REFUSED')
    # Before the historical validator, require exact frozen source and clean index.
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=frozen).decode().strip()!=FROZEN:raise ValueError('FROZEN_SHA_REFUSED')
    if any(not (frozen/n).is_file() or digest((frozen/n).read_bytes())!=v for n,v in tree(ROOT,FROZEN).items()):raise ValueError('FROZEN_SOURCE_REFUSED')
    save(out/'child-started.json',{'token':observed,'pid':os.getpid(),'parent_pid':os.getppid(),'frozen_sha':FROZEN,'status':'TOKEN_AND_SOURCE_VERIFIED'})
    if smoke:return 0
    from tools.stack_replay_v1 import execute
    row=execute([sys.executable,'-B','tools/pr1_native_gate_v1.py','--frozen',frozen,
                 '--out',out/'pr1-native-transition'],ROOT,out,'pr1-native-transition',timeout=10800)
    save(out/'child-result.json',row)
    return row['exit_code']

def top(out,frozen,smoke):
    from guardian import windows as win
    from tools import restricted_exec_v1 as trusted
    from tools.restricted_startup_v1 import launch
    out.mkdir(parents=True,exist_ok=False)
    before=current();target=Path(__file__).resolve()
    args=['--child','--out',str(out),'--frozen',str(frozen)]+(['--smoke'] if smoke else [])
    if before['elevated']:
        result=trusted.top(out/'restricted.json',out/'restricted-proof.json',2700,target,args)
        ok=result.get('status')=='EXECUTED' and result.get('target_exit_code')==0
        path='ELEVATED_TWO_STAGE'
    else:
        if not permitted(before):raise ValueError('CALLER_TOKEN_REFUSED')
        # Existing non-elevated path, now with pre-resume token equality and exit/marker checks.
        marker=out/'ordinary.marker'
        argsv=trusted.wrapped_argv(target,args,marker,out/'ordinary.stdout',out/'ordinary.stderr')
        result=launch('ordinary-verified-child','CreateProcessW',None,before,marker,argsv,timeout=9000,expected_token=before)
        ok=result.get('child_matches_expected') is True and result.get('started') is True
        path='NON_ELEVATED_EXACT_TOKEN'
    after=current()
    if after!=before:ok=False
    started=out/'child-started.json'
    if not started.is_file():ok=False
    else:
        record=json.loads(started.read_bytes())
        if record.get('status')!='TOKEN_AND_SOURCE_VERIFIED' or not permitted(record['token']) or record['token']['user_sha256']!=before['user_sha256']:ok=False
    save(out/'launch.json',{'status':'PASS' if ok else 'HOLD','path':path,'parent_before':before,'parent_after':after,'launch':result,'smoke_only':smoke,'production':'HOLD'})
    return 0 if ok else 1

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--frozen',type=Path,required=True);p.add_argument('--child',action='store_true');p.add_argument('--smoke',action='store_true');a=p.parse_args()
    if os.name!='nt':raise SystemExit('NOT_COVERED_WINDOWS')
    raise SystemExit(child(a.out.resolve(),a.frozen.resolve(),a.smoke) if a.child else top(a.out.resolve(),a.frozen.resolve(),a.smoke))
