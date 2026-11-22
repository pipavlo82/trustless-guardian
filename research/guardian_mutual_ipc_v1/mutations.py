"""Physical one-site mutation witnesses. Assertion failures, not crashes, establish kills."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
SPECS=[
 ('signature','        key.verify(bytes.fromhex(sig), DOMAIN + encode(p))','        pass # removed signature check','test_signature'),
 ('session','p["session_id"] == context["session_id"]','True','test_wrong_session'),
 ('challenge','p["client_challenge"] == context["client_challenge"]','True','test_wrong_challenge'),
 ('channel','p["channel_id"] == context["channel_id"]','True','test_wrong_channel'),
 ('authority','all(p[k] == trust[k] for k in ("broker_id", "trust_root_version", "key_id"))','True','test_wrong_broker'),
 ('version','p["protocol"] == PROTOCOL','True','test_wrong_version'),
 ('phase','p["phase"] == phase','True','test_wrong_phase'),
 ('request','p["request_sha256"] == digest(request)','True','test_wrong_request'),
 ('expiry','p["issued_at"] <= now < p["expires_at"]','True','test_expired_reply'),
 ('deadline','0 <= self.clock() - self.started <= TTL','True','test_deadline'),
 ('one-shot','self.phase == phase and phase in ("hello", "result")','True','test_replay'),
 ('revocation','trust["revoked"] is False','True','test_revoked_trust'),
 ('trust-time','trust["not_before"] <= now < trust["expires_at"]','True','test_expired_trust'),
 ('hold-only','and value["grant_issued"] is False and value["tool_executed"] is False','and value["grant_issued"] is False','test_no_execution_promotion'),
]


def main(out):
    out=Path(out);out.mkdir(parents=True,exist_ok=False);results=[]
    with tempfile.TemporaryDirectory(prefix='guardian-mutual-mutations-') as td:
        d=Path(td)
        for rel in ('research/guardian_mutual_ipc_v1','research/auth_gateway_v1'):
            shutil.copytree(ROOT/rel,d/rel,ignore=shutil.ignore_patterns('__pycache__'))
        f=d/'research/guardian_mutual_ipc_v1/protocol.py';raw=f.read_bytes()
        def run(label,test):
            env=__import__('os').environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env.pop('PYTHONPATH',None)
            cmd=[sys.executable,'-B']+(['-O'] if sys.flags.optimize else [])+['-m','unittest','-v','research.guardian_mutual_ipc_v1.tests.test_protocol.ProtocolTests.'+test]
            try:
                p=subprocess.run(cmd,cwd=d,env=env,capture_output=True,timeout=30)
                (out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
                return p.returncode,p.stderr.decode(errors='replace')
            except subprocess.TimeoutExpired:return None,'TIMEOUT'
        for name,old,new,test in SPECS:
            count=raw.decode().count(old);b,_=run(name+'-baseline',test)
            if count!=1:results.append({'id':name,'status':'NOT_APPLIED','matches':count});continue
            try:
                f.write_bytes(raw.decode().replace(old,new,1).encode());rc,stderr=run(name+'-mutant',test)
                healthy,_=run(name+'-positive','test_hold_only')
            finally:f.write_bytes(raw)
            restored,_=run(name+'-restored',test)
            if b!=0 or restored!=0 or healthy!=0:status='CONTROL_BROKEN'
            elif rc==0:status='SURVIVED'
            elif rc==1 and 'AssertionError' in stderr and '\nERROR:' not in stderr:status='KILLED'
            else:status='CRASHED'
            results.append({'id':name,'status':status,'matches':count,'baseline_exit':b,'mutant_exit':rc,'positive_exit':healthy,
                            'restored_exit':restored,'restored_bytes':f.read_bytes()==raw,'original_sha256':hashlib.sha256(raw).hexdigest()})
        # Explicitly demonstrate a harness error is a non-kill.
        rc,err=run('harness-error','test_missing_harness_sentinel')
        sentinel={'status':'CRASHED' if rc!=0 and 'ERROR:' in err else 'CONTROL_BROKEN','exit':rc}
    report={'results':results,'counts':{s:sum(x['status']==s for x in results) for s in ('KILLED','SURVIVED','CRASHED','NOT_APPLIED','CONTROL_BROKEN')},
            'harness_error_non_kill':sentinel,'passed':all(x['status']=='KILLED' for x in results) and sentinel['status']=='CRASHED'}
    (out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(report,sort_keys=True));return 0 if report['passed'] else 1


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);a=p.parse_args();raise SystemExit(main(a.out))
