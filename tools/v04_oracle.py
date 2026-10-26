"""Separate process oracle. Imports neither Guardian nor its policy/IPC/journal."""
import argparse
import hashlib
import json
from pathlib import Path

def inspect(v):
    checks={}
    if v['kind']=='token':
        p=v['probe'];rows=p['rows'];identity=p['process']
        checks['positive_level_one']=rows[0]['observed']['level']==1 and rows[0]['decision']['accepted']
        checks['token_identity']=all(r['observed']['appcontainer_sid']==identity['appcontainer_sid'] and r['observed']['user_sha256']==identity['user_sha256'] and r['observed']['token_type']==2 and not r['observed']['elevated'] and r['observed']['capability_count']==0 for r in rows)
        checks['negative_levels']=all(r['observed']['level']==r['requested'] and not r['decision']['accepted'] and r['decision']['reason']=='IPC_IMPERSONATION_LEVEL' for r in rows[1:])
        checks['identification_not_impersonation']=not rows[0]['token_io']['opened'] and all(r['token_io']['opened'] for r in rows[1:])
        checks['clean_completion']=all(r['client'].get('completed') and r['thread_finished'] and r['thread_after']=={'present':False,'winerror':1008} for r in rows)
        checks['protected_unchanged']=v['before_hex']==v['after_hex']
    else:
        pos=v['positive'];row=v['observation'];r=row['response'].get('response',{});fault=v['fault']
        checks['positive']=pos['server_exit']==0 and pos['response'].get('response',{}).get('execution')=='COMMITTED' and bytes.fromhex(pos['after_hex'])==b'approved:positive'
        before=bytes.fromhex(v['before_hex']);after=bytes.fromhex(row['after_hex'])
        checks['host_digest']=hashlib.sha256(before).hexdigest()==row['before_sha256'] and hashlib.sha256(after).hexdigest()==row['after_sha256']
        host=row['independent_host'];token=host['server']['token']
        checks['independent_host_bytes']=host['before']['hex']==before.hex() and host['after']['hex']==after.hex()
        checks['independent_broker_token']=token['appcontainer_sid']==v['broker_sid'] and token['appcontainer'] and not token['elevated'] and token['integrity_sid']=='S-1-16-4096' and token['capability_count']==0
        expected=v['expected']
        checks['actual_bytes']=after==bytes.fromhex(expected['after_hex'])
        checks['controlled_process']=row['server_exit']==expected['exit']
        if expected['exit']==0:
            checks['no_false_nonexecution']=r.get('status')=='UNVERIFIABLE' and r.get('decision')=='DENY' and r.get('execution')=='RECOVERY_REQUIRED' and r.get('retry_permitted') is False
            checks['fault_reached']=bool(fault.get('events')) or v['case']=='sqlite_commit_failure'
        else:
            checks['no_fabricated_crash_reply']=not r
        restart=v['restart'];reply=restart['response'].get('response',{})
        checks['restart_control']=restart['server_exit']==0 and restart['unchanged'] and reply.get('reason')==expected['restart_reason']
        if expected['restart_reason']=='RECOVERY_REQUIRED':checks['restart_preserves_ambiguity']=reply.get('status')=='UNVERIFIABLE' and reply.get('execution')=='RECOVERY_REQUIRED' and reply.get('retry_permitted') is False
        checks['durable_state']=v['journal'][-1]['state']==expected['state'] if expected['state'] else len(v['journal'])==1
    return {'passed':all(checks.values()),'checks':checks,'external_execution':'UNVERIFIABLE'}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('input',type=Path,nargs='?');p.add_argument('--snapshot',type=Path);p.add_argument('--pid',type=int);p.add_argument('--out',type=Path);a=p.parse_args()
    if a.snapshot:
        import v04_native as native
        raw=a.snapshot.read_bytes();value={'hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'token':native.process(a.pid)}
        a.out.write_bytes(json.dumps(value,sort_keys=True,indent=2).encode()+b'\n');raise SystemExit(0)
    try:r=inspect(json.loads(a.input.read_bytes()))
    except Exception as e:r={'passed':False,'control_broken':repr(e)}
    print(json.dumps(r,sort_keys=True));raise SystemExit(0 if r['passed'] else 2 if 'control_broken' in r else 1)
