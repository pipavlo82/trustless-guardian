"""Single physical edits in disposable copies; crashes never count as semantic kills."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(json.dumps(value,sort_keys=True,indent=2).encode()+b'\n')


def classify(base,mutated,restored,restored_bytes):
    def sound(r):return r is not None and r['positive_ok'] and not r['negative_wrote']
    if not sound(base) or not sound(restored) or not restored_bytes:return 'CONTROL_BROKEN'
    if mutated is None:return 'CRASHED'
    if not mutated['positive_ok']:return 'CONTROL_BROKEN'
    return 'KILLED' if mutated['negative_wrote'] else 'SURVIVED'


def mutate(text,kind):
    if kind=='acl':
        old="rights = 'FA' if writable else 'GRGX'";new="rights = 'FA'  # physical ACL mutation"
    elif kind=='nonce_consumption':
        old="db.execute('INSERT INTO consumed VALUES(?)',(request['nonce'],));db.commit()"
        new="db.commit()  # physical nonce-consumption mutation"
    else:
        matches=[line for line in text.splitlines() if '# GUARD '+kind in line and line.split('# GUARD ')[1].strip()==kind]
        if len(matches)!=1:raise ValueError('mutation not uniquely applicable')
        old=matches[0]
        if kind in ('policy_pin','resource_identity','enforcement'):
            new=old[:len(old)-len(old.lstrip())]+('if True:' if kind=='enforcement' else 'if False:')+'  # physical mutation'
        else:
            # Keep the original return body, replacing exactly the condition.
            new=old[:old.index('if ')]+ 'if False: return'+old.split(':return',1)[1]
    if text.count(old)!=1:raise ValueError('mutation not uniquely applicable')
    return text.replace(old,new)


def run(out):
    out=out.absolute();out.mkdir(parents=True,exist_ok=True);started=time.perf_counter()
    kinds=['actor','action','resource','scope','version','expiry','replay','evidence','precondition','content',
           'policy_pin','resource_identity','enforcement','nonce_consumption','acl']
    rows=[]
    for kind in kinds:
        checkout=out/kind/'checkout';checkout.mkdir(parents=True)
        shutil.copytree(ROOT/'guardian',checkout/'guardian',ignore=shutil.ignore_patterns('__pycache__'))
        (checkout/'tools').mkdir()
        for name in ('lab.py','agent_worker.py','mutation_witness.py'):shutil.copyfile(ROOT/'tools'/name,checkout/'tools'/name)
        shutil.copyfile(ROOT/'runtime-lock.json',checkout/'runtime-lock.json')
        (checkout/'build/runtime').mkdir(parents=True)
        shutil.copyfile(ROOT/'build/runtime/python-3.12.10-embed-amd64.zip',checkout/'build/runtime/python-3.12.10-embed-amd64.zip')
        file=checkout/'guardian'/('windows.py' if kind=='acl' else 'broker.py' if kind in ('policy_pin','resource_identity','enforcement','nonce_consumption') else 'policy.py')
        original=file.read_bytes();original_hash=hashlib.sha256(original).hexdigest()
        def execute(phase):
            destination=out/kind/phase
            cmd=[sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),str(checkout/'tools/mutation_witness.py'),kind,'--out',str(destination)]
            destination.mkdir(parents=True)
            try:
                p=subprocess.run(cmd,capture_output=True,timeout=90)
                stdout,stderr,code,error=p.stdout,p.stderr,p.returncode,None
            except subprocess.TimeoutExpired as exc:
                stdout,stderr,code,error=exc.stdout or b'',exc.stderr or b'',None,'TIMEOUT'
            except OSError as exc:
                stdout,stderr,code,error=b'',str(exc).encode(),None,'PROCESS_UNAVAILABLE'
            (destination/'stdout.log').write_bytes(stdout);(destination/'stderr.log').write_bytes(stderr)
            write(destination/'command.json',{'argv':cmd,'exit_code':code,'infrastructure_error':error})
            result=destination/'witness.json'
            return json.loads(result.read_bytes()) if code==0 and result.exists() else None
        base=execute('baseline');applied=False;mutated=None
        try:
            changed=mutate(original.decode('utf-8'),kind).encode('utf-8')
            file.write_bytes(changed);applied=True;mutated=execute('mutated')
        except ValueError:pass
        finally:file.write_bytes(original)
        restored=execute('restored');restored_bytes=hashlib.sha256(file.read_bytes()).hexdigest()==original_hash
        status=classify(base,mutated,restored,restored_bytes) if applied else 'NOT_APPLIED'
        row={'id':kind,'classification':status,'source':str(file.relative_to(checkout)),
             'original_sha256':original_hash,'restored_byte_exact':restored_bytes,'applied':applied}
        if applied:row['mutated_sha256']=hashlib.sha256(changed).hexdigest()
        rows.append(row);print(json.dumps(row),flush=True)
    counts={status:sum(r['classification']==status for r in rows) for status in ('KILLED','SURVIVED','CRASHED','NOT_APPLIED','CONTROL_BROKEN')}
    report={'schema':'guardian.mutations.v0','mutants':rows,'counts':counts,'seconds':time.perf_counter()-started,
      'unexecuted_boundaries':['hardlink/reparse broker guard','kernel/AppContainer internals','concurrent broker instances','crash recovery']}
    write(out/'report.json',report)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();report=run(a.out)
    raise SystemExit(report['counts']['KILLED']!=len(report['mutants']))
