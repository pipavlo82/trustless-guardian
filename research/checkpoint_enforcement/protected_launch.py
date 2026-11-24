"""Trusted local launch boundary. No arbitrary module, code, command or image input.
Use python -I -B protected_launch.py. Not an agent-facing API.
"""
import argparse,hashlib,json,os,sys
from pathlib import Path

def main():
    arg=argparse.ArgumentParser()
    arg.add_argument('mode',choices=['dispatch','recover'])
    arg.add_argument('root');arg.add_argument('--manifest-sha256',required=True)
    arg.add_argument('--config',required=True);arg.add_argument('--config-sha256',required=True)
    a=arg.parse_args();base=Path(__file__).resolve().parent
    if not sys.flags.isolated:raise RuntimeError('ISOLATED_PYTHON_REQUIRED')
    raw=(base/'manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=a.manifest_sha256:raise RuntimeError('DISTRIBUTION_PIN')
    manifest=json.loads(raw)
    actual={p.relative_to(base).as_posix() for p in base.rglob('*') if p.is_file()}
    if actual!=set(manifest)|{'manifest.json'}:raise RuntimeError('DISTRIBUTION_INVENTORY')
    if any(hashlib.sha256((base/n).read_bytes()).hexdigest()!=h for n,h in manifest.items()):raise RuntimeError('DISTRIBUTION_BYTES')
    os.environ['GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED']='1'
    os.environ['GUARDIAN_CHECKPOINT_CONFIG']=a.config
    os.environ['GUARDIAN_CHECKPOINT_CONFIG_SHA256']=a.config_sha256
    sys.path.insert(0,str(base))
    root=Path(a.root).resolve()
    if a.mode=='recover':
        from research.scoped_execution_lab_v3.reconcile_v3_hardened import reconcile
        result=reconcile(root)
    else:
        # A completed or uncertain job is never a dispatch retry. Recovery has a
        # separate gated entrypoint; even a lost response cannot trigger a launch.
        if (root/'job').exists():
            print(json.dumps({'status':'RECOVERY_REQUIRED','reason':'EXISTING_JOB_NO_AUTOMATIC_DISPATCH','dispatches':0,'retry_permitted':False}))
            return 2
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
        from research.scoped_execution_lab_v3 import lab
        from research.scoped_execution_lab_v3.unified_state import UnifiedState
        import time
        secret=json.loads(sys.stdin.readline());read=lambda n:json.loads((root/n).read_bytes())
        request=read('intent/request.json');grant=read('intent/grant.json');policy=read('policy.json')
        pins=read('public.json')
        result=lab.execute(request,grant,Ed25519PublicKey.from_public_bytes(bytes.fromhex(pins['grant_public'])),
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret['receipt_seed'])),
            UnifiedState(root/'state.sqlite',lab.SCOPE),policy,policy['sid'],int(time.time()),root/'job')
    print(json.dumps(result,sort_keys=True))
    return 0 if result.get('status') in ('OBSERVED_SYNTHETIC_RESULT','LOCAL_RECONCILED_EXTERNAL_HOLD') else 2
if __name__=='__main__':raise SystemExit(main())
