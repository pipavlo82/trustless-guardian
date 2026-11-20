"""Explicit LAB-only post-IPC admission. Original broker is unchanged/HOLD-only."""
import argparse
import json
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.guardian_mutual_ipc_v1.broker import serve
from research.replay_challenge_v1.durable import DurableSecurityState
from research.scoped_execution_lab_v1 import lab

def main():
    p=argparse.ArgumentParser()
    for name in ('channel','sid','ready','out','trust','mode'):p.add_argument('--'+name,required=True)
    a=p.parse_args();out=Path(a.out)
    secret=json.loads(sys.stdin.buffer.readline(4096))
    broker_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret['key']))
    trust=json.loads(Path(a.trust).read_bytes())
    result=serve(a.channel,a.sid,a.ready,out/'broker.json',trust,broker_key)
    now=int(time.time())
    policy={'schema':'guardian.synthetic-policy.v1','enabled':True,'revoked':a.mode=='revoked_policy','sid':a.sid,'epoch':1,'not_before':now-1,'expires_at':now+90}
    (out/'policy.json').write_bytes(lab.canonical(policy)+b'\n')
    try:
        request=lab.admit_live_result(result,a.sid,policy,now)
        key=Ed25519PrivateKey.generate();receipt_key=Ed25519PrivateKey.generate()
        grant=lab.issue(request,key,a.sid,now)
        state=DurableSecurityState(out/'state.sqlite',lab.SCOPE)
        executed=lab.execute(request,grant,key.public_key(),receipt_key,state,policy,a.sid,now,out/'job')
        replay=lab.execute(request,grant,key.public_key(),receipt_key,state,policy,a.sid,now,out/'replay')
        state.close()
        summary={'execution':executed,'replay':replay,'lab_grant_issued':True}
    except lab.SecurityError as error:
        summary={'execution':{'status':'REFUSED','reason':error.code,'launches':0},'lab_grant_issued':False}
    (out/'execution.json').write_bytes(lab.canonical(summary)+b'\n')
    print(json.dumps(summary,sort_keys=True))

if __name__=='__main__':main()
