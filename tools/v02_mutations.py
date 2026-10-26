"""Physical single-guard edits, fresh real processes, original/restored controls."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.mutations import classify,write

KINDS=['envelope_pin','caller_identity','server_identity','policy_pin','resource_identity',
       'directory_identity','enforcement','recovery_gate','filetype','acl','journal_state']


def edit(kind,checkout):
    filename=('guardian/protocol.py' if kind=='envelope_pin' else 'guardian/ipc.py' if kind in ('caller_identity','server_identity')
              else 'guardian/broker.py' if kind=='filetype' else 'tools/v02_lab.py' if kind=='acl'
              else 'guardian/recovery.py' if kind=='journal_state' else 'guardian/hardened.py')
    file=checkout/filename;original=file.read_bytes();text=original.decode()
    if kind=='caller_identity':
        old="""    if (not observed['appcontainer'] or observed['elevated'] or observed['capability_count'] != 0
        or observed['integrity_sid'] != 'S-1-16-4096' or observed['user_sha256'] != expected_user
        or observed['appcontainer_sid'] != expected_sid):  # V02 caller_identity"""
        new='    if False:  # physical caller-token admission mutation'
    elif kind=='acl':
        old="        self.acl(self.resource,broker='GRGW')";new="        self.acl(self.resource,broker='GRGW',agent='GRGW')"
    else:
        marker=('# GUARD ' if kind=='filetype' else '# V02 ')+kind
        lines=[line for line in text.splitlines() if line.rstrip().endswith(marker)]
        if len(lines)!=1:raise ValueError('mutation not unique')
        old=lines[0];start=old.index('if ');end=old.index(':',start)
        # Type annotations/dicts do not occur inside these selected predicates.
        new=old[:start]+'if False'+old[end:]
    if text.count(old)!=1:raise ValueError('mutation not unique')
    changed=text.replace(old,new).encode();return file,original,changed,filename


def run(out):
    out=out.absolute();out.mkdir(parents=True,exist_ok=True);rows=[];started=time.perf_counter()
    for kind in KINDS:
        checkout=out/kind/'checkout';checkout.mkdir(parents=True)
        shutil.copytree(ROOT/'guardian',checkout/'guardian',ignore=shutil.ignore_patterns('__pycache__'))
        (checkout/'tools').mkdir()
        for name in ('lab.py','agent_worker.py','v02_lab.py','v02_worker.py','v02_campaign.py'):
            shutil.copyfile(ROOT/'tools'/name,checkout/'tools'/name)
        shutil.copyfile(ROOT/'runtime-lock.json',checkout/'runtime-lock.json')
        (checkout/'build/runtime').mkdir(parents=True)
        shutil.copyfile(ROOT/'build/runtime/python-3.12.10-embed-amd64.zip',checkout/'build/runtime/python-3.12.10-embed-amd64.zip')
        def execute(phase):
            destination=out/kind/phase;destination.mkdir()
            argv=[sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),str(checkout/'tools/v02_campaign.py'),'--witness',kind,'--out',str(destination)]
            try:
                p=subprocess.run(argv,capture_output=True,timeout=70);code=p.returncode;stdout=p.stdout;stderr=p.stderr
            except subprocess.TimeoutExpired as exc:code=None;stdout=exc.stdout or b'';stderr=exc.stderr or b''
            (destination/'stdout.log').write_bytes(stdout);(destination/'stderr.log').write_bytes(stderr)
            write(destination/'command.json',{'argv':argv,'exit_code':code})
            f=destination/'witness.json'
            return json.loads(f.read_bytes()) if code==0 and f.exists() else None
        base=execute('baseline');applied=False;mutated=None;file=None
        try:
            file,original,changed,filename=edit(kind,checkout);file.write_bytes(changed);applied=True
            mutated=execute('mutated')
        except ValueError:pass
        finally:
            if file:file.write_bytes(original)
        restored=execute('restored');exact=file is not None and file.read_bytes()==original
        status=classify(base,mutated,restored,exact) if applied else 'NOT_APPLIED'
        row={'id':kind,'classification':status,'applied':applied,'restored_byte_exact':exact,
             'source':filename if file else None,'original_sha256':hashlib.sha256(original).hexdigest() if file else None,
             'mutated_sha256':hashlib.sha256(changed).hexdigest() if file else None}
        rows.append(row);print(json.dumps(row),flush=True)
    counts={name:sum(r['classification']==name for r in rows) for name in ('KILLED','SURVIVED','CRASHED','NOT_APPLIED','CONTROL_BROKEN')}
    report={'schema':'guardian.mutations.v02','mutants':rows,'counts':counts,'seconds':time.perf_counter()-started,
            'passed':counts['KILLED']==len(KINDS),'meaning':'finite selected boundaries; historic v0 15 controls are a separate population'}
    write(out/'report.json',report);return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();raise SystemExit(not run(a.out)['passed'])
