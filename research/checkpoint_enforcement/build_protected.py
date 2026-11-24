"""Build a minimal research distribution; never edits legacy or frozen sources.
The artifact excludes legacy executors. This is not a host OS access-control policy.
"""
from pathlib import Path
import hashlib,json,shutil,sys

def build(root,dest):
    root=Path(root).resolve();dest=Path(dest).resolve();dest.mkdir(exist_ok=False)
    files=[]
    for folder in ['research/auth_gateway_v1','research/replay_challenge_v1']:
        files.extend(p.relative_to(root).as_posix() for p in (root/folder).glob('*.py') if p.name!='execution.py')
    for folder,names in {
        'guardian':['__init__.py','windows.py'],
        'research/scoped_execution_lab_v3':['__init__.py','lab.py','unified_state.py','unified_admission.py','atomic_receipt.py','lifecycle_support.py','verify_unified_independent.py','reconcile_v3_hardened.py','guardian_rc2_server.py','image.json','worker'],
        'research/checkpoint_enforcement':['__init__.py','gate.py','checkpoint_verify.py'],
        'research/guardian_mutual_ipc_v1':['__init__.py','broker.py','protocol.py'],
        'research/resonance_guardian_v1':['__init__.py','broker_host.py'],
    }.items():
        files.extend(folder+'/'+n for n in names if (root/folder/n).exists())
    for n in files:
        p=dest/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(root/n,p)
    shutil.copy2(root/'research/checkpoint_enforcement/protected_launch.py',dest/'protected_launch.py')
    gate=dest/'research/checkpoint_enforcement/gate.py';text=gate.read_text()
    if text.count('PACKAGED_REQUIRED = False')!=1:raise RuntimeError('PROTECTED_BUILD_SENTINEL')
    gate.write_text(text.replace('PACKAGED_REQUIRED = False','PACKAGED_REQUIRED = True'),encoding='utf-8',newline='\n')
    manifest={p.relative_to(dest).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(dest.rglob('*')) if p.is_file()}
    raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    (dest/'manifest.json').write_bytes(raw)
    return {'files':len(manifest),'manifest_sha256':hashlib.sha256(raw).hexdigest(),'scope':'MINIMAL_RESEARCH_DISTRIBUTION_NOT_OS_SANDBOX'}
if __name__=='__main__':print(json.dumps(build(Path(__file__).resolve().parents[2],sys.argv[1])))
