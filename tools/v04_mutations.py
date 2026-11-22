"""New population only: physical edits, positive/original/restored OS witnesses."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[1]

MUTANTS={
 'ordinary_exception_legacy':('guardian/hardened.py','except Exception:  # V04 ordinary_exception_boundary',"except (OSError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,RecursionError,__import__('sqlite3').Error):  # V04 ordinary_exception_boundary",'runtime_after_write',True),
 'recovery_response':('guardian/hardened.py',"'execution':'RECOVERY_REQUIRED','retry_permitted':False}  # V02 recovery_gate","'execution':'NOT_EXECUTED','retry_permitted':False}  # V02 recovery_gate",'crash_written',False),
 'dispatch_outcome':('guardian/dispatch.py',"'reason':'DISPATCH_OUTCOME_UNCERTAIN','execution':'RECOVERY_REQUIRED'","'reason':'DISPATCH_OUTCOME_UNCERTAIN','execution':'NOT_EXECUTED'",'dispatch_return_failure',False),
 'readback_consistency':('guardian/hardened.py',"if after!=intended:raise OSError('READBACK_MISMATCH')","if False:raise OSError('READBACK_MISMATCH')",'readback_mismatch',False),
 'same_identity_pipe_level':('guardian/ipc.py',"if observed['impersonation_level']!=1:raise PermissionError('IPC_IMPERSONATION_LEVEL')","if False:raise PermissionError('IPC_IMPERSONATION_LEVEL')",'token',False),
}

def write(path,obj):path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(json.dumps(obj,sort_keys=True,indent=2).encode()+b'\n')
def valid_control(value,case):
    if not value or value.get('control_broken'):return False
    c=value['checks']
    keys=('positive_level_one','clean_completion','token_identity','protected_unchanged') if case=='token' else ('positive','controlled_process','host_digest','independent_host_bytes','independent_broker_token')
    return all(c.get(k) for k in keys)
def classify(base,mutated,restored,case,applied,exact):
    if not applied:return 'NOT_APPLIED'
    if not exact or not all(valid_control(x,case) and x['passed'] for x in (base,restored)):return 'CONTROL_BROKEN'
    if mutated is None:return 'CRASHED'
    if not valid_control(mutated,case):return 'CONTROL_BROKEN'
    return 'SURVIVED' if mutated['passed'] else 'KILLED'
def run(out):
    out=out.absolute();out.mkdir(parents=True,exist_ok=False);rows=[]
    for name,(file,old,new,case,legacy) in MUTANTS.items():
        checkout=out/name/'checkout';checkout.mkdir(parents=True)
        for folder in ('guardian','tools'):shutil.copytree(ROOT/folder,checkout/folder,ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copyfile(ROOT/'runtime-lock.json',checkout/'runtime-lock.json')
        (checkout/'build/runtime').mkdir(parents=True);shutil.copyfile(ROOT/'build/runtime/python-3.12.10-embed-amd64.zip',checkout/'build/runtime/python-3.12.10-embed-amd64.zip')
        def execute(phase):
            path=out/name/phase;argv=[sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),str(checkout/'tools/v04_campaign.py'),'--out',str(path),'--witness',case]+(['--legacy-dispatch'] if legacy else [])
            started=time.perf_counter()
            try:p=subprocess.run(argv,capture_output=True,timeout=120);code=p.returncode;stdout=p.stdout;stderr=p.stderr
            except subprocess.TimeoutExpired as e:code=None;stdout=e.stdout or b'';stderr=e.stderr or b''
            path.mkdir(parents=True,exist_ok=True);(path/'stdout.log').write_bytes(stdout);(path/'stderr.log').write_bytes(stderr)
            write(path/'command.json',{'argv':argv,'exit_code':code,'seconds':time.perf_counter()-started})
            target=path/case/'witness.json'
            return json.loads(target.read_bytes()) if code in (0,1) and target.exists() else None
        source=checkout/file;original=source.read_bytes();base=execute('baseline');applied=original.decode().count(old)==1;changed=None;mutated=None
        try:
            if applied:changed=original.decode().replace(old,new).encode();source.write_bytes(changed);mutated=execute('mutated')
        finally:source.write_bytes(original)
        restored=execute('restored');exact=source.read_bytes()==original
        row={'id':name,'case':case,'legacy_dispatch':legacy,'source':file,'applied':applied,'restored_byte_exact':exact,
             'original_sha256':hashlib.sha256(original).hexdigest(),'mutated_sha256':hashlib.sha256(changed).hexdigest() if changed else None,
             'classification':classify(base,mutated,restored,case,applied,exact)}
        rows.append(row);print(json.dumps(row),flush=True)
    counts={k:sum(r['classification']==k for r in rows) for k in ('KILLED','SURVIVED','CRASHED','NOT_APPLIED','CONTROL_BROKEN')}
    report={'schema':'guardian.mutations.v04','mutants':rows,'counts':counts,'passed':all(r['classification']=='KILLED' for r in rows),
            'historical_populations_unchanged':True,'full_profile_level_gt1_reachability':'NOT_COVERED'}
    write(out/'report.json',report);return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();raise SystemExit(not run(a.out)['passed'])
