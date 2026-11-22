"""One physical edit at a time, original/restored OS witnesses, no crash-as-kill."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.lab import write

MUTANTS={
 'ambiguous_failure':('guardian/hardened.py',"if stage!='NOT_STARTED':  # V03 ambiguous_failure","if False:  # V03 ambiguous_failure",'post_write_failure'),
 'same_bytes':('guardian/recovery.py',"if i['before_sha256']==i['after_sha256']:state='RECOVERY_REQUIRED'  # V03 same_bytes","if False:state='RECOVERY_REQUIRED'  # V03 same_bytes",'same_bytes'),
 'base_user':('guardian/ipc.py',"or observed['user_sha256'] != expected_user","or False",'base_user'),
 'impersonation_level':('guardian/ipc.py',"if observed['impersonation_level']!=1:raise PermissionError('IPC_IMPERSONATION_LEVEL')","if False:raise PermissionError('IPC_IMPERSONATION_LEVEL')",'impersonation_level')}


def classify(base,mutant,restored,exact,applied):
    if not applied:return 'NOT_APPLIED'
    if not exact or not base or not restored or not all(r.get('positive_ok') and r.get('negative_ok') for r in (base,restored)):return 'CONTROL_BROKEN'
    if mutant is None:return 'CRASHED'
    if not mutant.get('positive_ok'):return 'CONTROL_BROKEN'
    return 'SURVIVED' if mutant.get('negative_ok') else 'KILLED'


def run(out):
    out=out.absolute();out.mkdir(parents=True,exist_ok=True);rows=[]
    for name,(file,old,new,witness) in MUTANTS.items():
        root=out/name/'checkout';root.mkdir(parents=True)
        shutil.copytree(ROOT/'guardian',root/'guardian',ignore=shutil.ignore_patterns('__pycache__'))
        (root/'tools').mkdir()
        for f in ('lab.py','agent_worker.py','v02_worker.py','v02_lab.py','v02_campaign.py','v03_worker.py','v03_campaign.py'):
            shutil.copyfile(ROOT/'tools'/f,root/'tools'/f)
        shutil.copyfile(ROOT/'runtime-lock.json',root/'runtime-lock.json');(root/'build/runtime').mkdir(parents=True)
        shutil.copyfile(ROOT/'build/runtime/python-3.12.10-embed-amd64.zip',root/'build/runtime/python-3.12.10-embed-amd64.zip')
        def execute(phase):
            dest=out/name/phase;dest.mkdir()
            argv=[sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),str(root/'tools/v03_campaign.py'),'--witness',witness,'--out',str(dest)]
            start=time.perf_counter()
            try:p=subprocess.run(argv,capture_output=True,timeout=90);code=p.returncode;stdout=p.stdout;stderr=p.stderr
            except subprocess.TimeoutExpired as e:code=None;stdout=e.stdout or b'';stderr=e.stderr or b''
            (dest/'stdout.log').write_bytes(stdout);(dest/'stderr.log').write_bytes(stderr)
            write(dest/'command.json',{'argv':argv,'exit_code':code,'seconds':time.perf_counter()-start})
            path=dest/'witness.json';return json.loads(path.read_bytes()) if code==0 and path.exists() else None
        original=(root/file).read_bytes();text=original.decode();base=execute('baseline');applied=text.count(old)==1;mutant=None;changed=None
        try:
            if applied:
                changed=text.replace(old,new).encode();(root/file).write_bytes(changed);mutant=execute('mutated')
        finally:(root/file).write_bytes(original)
        restored=execute('restored');exact=(root/file).read_bytes()==original
        row={'id':name,'classification':classify(base,mutant,restored,exact,applied),'applied':applied,'restored_byte_exact':exact,
             'source':file,'original_sha256':hashlib.sha256(original).hexdigest(),'mutated_sha256':hashlib.sha256(changed).hexdigest() if changed else None,
             'boundary_exercised':name!='impersonation_level'}
        rows.append(row);print(json.dumps(row),flush=True)
    counts={k:sum(r['classification']==k for r in rows) for k in ('KILLED','SURVIVED','CRASHED','NOT_APPLIED','CONTROL_BROKEN')}
    # A survivor is reported, never silently counted as a kill. Validation of the
    # experiment requires the explicitly declared pattern, not universal coverage.
    expected={'ambiguous_failure':'KILLED','same_bytes':'KILLED','base_user':'KILLED','impersonation_level':'SURVIVED'}
    report={'schema':'guardian.mutations.v03','mutants':rows,'counts':counts,'expected':expected,
            'passed':all(r['classification']==expected[r['id']] and r['restored_byte_exact'] for r in rows),
            'coverage_complete':False,'survivor_limitation':'Effective token level remains identification on this host; no level>1 negative OS witness was obtained.'}
    write(out/'report.json',report);return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();raise SystemExit(not run(a.out)['passed'])
