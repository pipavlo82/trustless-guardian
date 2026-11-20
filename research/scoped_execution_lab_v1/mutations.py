"""Physical mutations in disposable copies; exact restoration; crashes are non-kills."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
LAB='research/scoped_execution_lab_v1/lab.py'
GRANT='research/replay_challenge_v1/scoped_grant.py'
MUTANTS=[
 ('revocation',LAB,[("and policy['revoked'] is False","and True")],'test_revoked_policy'),
 ('client_sid',LAB,[("and ident.get('appcontainer_sid') == sid","and True")],'test_client_sid'),
 ('client_token',LAB,[("ident.get('appcontainer') is True","True")],'test_client_identity'),
 ('client_ack',LAB,[("and result.get('client_result') == {'op':'CLIENT_RESULT','code':73,'reason':'HOLD_GUARDIAN_GRANT_REQUIRED'}","and True")],'test_incomplete_ipc'),
 ('policy_binding',LAB,[("request['body'].get('policy_sha256') == sha(canonical(policy))","True")],'test_policy_binding'),
 ('signature',GRANT,[("public_key.verify(signature, canonical_json_bytes(payload))","pass  # physical signature guard removal")],'test_signature'),
 ('request_binding',GRANT,[("payload[\"binding\"] != expected_binding.as_dict()","False"),("payload[\"binding_sha256\"] != expected_binding.digest()","False")],'test_request'),
 ('worker_binding',GRANT,[("if payload[\"worker_sha256\"] != expected_worker_sha256:","if False:")],'test_worker'),
 ('image_binding',GRANT,[("if payload[\"image_identity\"] != expected_image_identity:","if False:")],'test_image'),
 ('isolation_inspect',LAB,[("h['Privileged'] is False","True")],'test_inspect_isolation'),
 ('independent_signature','research/scoped_execution_lab_v1/verify.mjs',[("crypto.verify(null,Buffer.from(canon(x.payload)),key(pub),sig)","true")],'test_receipt_signature'),
 ('independent_recompute','research/scoped_execution_lab_v1/verify.mjs',[("so.equals(Buffer.from(want)) && se.length===0","true")],'test_signed_wrong_result'),
 ('independent_outcome','research/scoped_execution_lab_v1/verify.mjs',[("Object.entries(observed).filter(([k])=>k!=='outcome_sha256').every(([k,v])=>o[k]===v)","true")],'test_outcome_contradiction'),
]

def run(out):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False);rows=[]
    with tempfile.TemporaryDirectory(prefix='guardian-lab-mutants-') as temp:
        repo=Path(temp)/'repo';shutil.copytree(ROOT,repo,ignore=shutil.ignore_patterns('.git','build','__pycache__'))
        def call(label,test):
            args=[sys.executable,'-B']+(['-O'] if sys.flags.optimize else [])+['-m','unittest','research.scoped_execution_lab_v1.test_lab.LabTests.'+test,'-v']
            p=subprocess.run(args,cwd=repo,capture_output=True,timeout=90)
            (out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
            return p.returncode,p.stderr.decode(errors='replace')
        for name,file,replacements,test in MUTANTS:
            f=repo/file;raw=f.read_bytes();text=raw.decode();counts=[text.count(a) for a,b in replacements]
            if counts!=[1]*len(counts):rows.append({'id':name,'status':'NOT_APPLIED','matches':counts});continue
            before,_=call(name+'-before',test)
            for a,b in replacements:text=text.replace(a,b,1)
            try:
                f.write_bytes(text.encode());healthy,_=call(name+'-healthy','test_healthy_worker_and_node');code,stderr=call(name+'-mutant',test)
            finally:f.write_bytes(raw)
            after,_=call(name+'-restored',test)
            if before or healthy or after:status='CONTROL_BROKEN'
            elif code==0:status='SURVIVED'
            elif code==1 and 'FAIL:' in stderr and 'AssertionError' in stderr and '\nERROR:' not in stderr:status='KILLED'
            else:status='CRASHED'
            rows.append({'id':name,'file':file,'replacements':replacements,'matches':counts,'baseline_exit':before,'healthy_exit':healthy,'mutant_exit':code,'restored_exit':after,'status':status,'restored_bytes':f.read_bytes()==raw,'source_sha256':hashlib.sha256(raw).hexdigest()})
            print(name,status,flush=True)
    report={'mutants':rows,'counts':{s:sum(r['status']==s for r in rows) for s in ('KILLED','SURVIVED','CRASHED','NOT_APPLIED','CONTROL_BROKEN')}}
    (out/'results.json').write_text(json.dumps(report,indent=2)+'\n',newline='\n')
    return 0 if all(r['status']=='KILLED' for r in rows) else 1
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);a=p.parse_args();raise SystemExit(run(a.out))
