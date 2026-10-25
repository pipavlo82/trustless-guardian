"""Separate-process receipt oracle: no imports from broker, policy, IPC or journal."""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def canon(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def sha(v):return hashlib.sha256(v).hexdigest()


def verify(record,pin,head,principal,identity):
    try:
        b=record['body'];r=b['request'];p=b['policy'];d=b['decision'];now=b['verification_time']
        before=base64.b64decode(b['before_base64'],validate=True);after=base64.b64decode(b['after_base64'],validate=True)
        intact=(set(record)=={'schema','previous','body','sha256'} and record['schema']=='guardian.evidence.v0'
          and record['previous']=='0'*64 and head==record['sha256']==sha(canon({'previous':record['previous'],'body':b}))
          and pin==b['policy_sha256']==sha(canon(p)) and b['request_sha256']==sha(canon(r))
          and b['before_sha256']==sha(before) and b['after_sha256']==sha(after))
        fields={'schema','actor','action','resource','scope','policy_version','expires_at','nonce','content','evidence'}
        authorized=(set(r)==fields and r['schema']=='guardian.action.v0' and p['schema']=='guardian.policy.v0'
          and b['profile']=='guardian.local-file.v02' and b['principal']==principal==r['actor'] and principal in p['actors']
          and b['resource_identity']==identity and r['action']==p['action']=='replace_utf8'
          and r['resource']==p['resource'] and r['scope']==p['scope'] and r['policy_version']==p['version']
          and type(now)==int and type(r['expires_at'])==int and now<=r['expires_at']<=now+p['max_ttl']
          and isinstance(r['nonce'],str) and 1<=len(r['nonce'])<=64 and r['nonce'] not in b['used_nonces']
          and set(r['evidence'])=={'before_sha256'} and r['evidence']['before_sha256']==sha(before)
          and isinstance(r['content'],str) and r['content'].startswith(p['content_prefix'])
          and len(r['content'].encode())<=p['max_bytes'])
        scope={'actor':principal,'action':r['action'],'resource':r['resource'],'scope':r['scope'],
          'policy_version':p['version'],'expires_at':r['expires_at'],'nonce':r['nonce'],'content_sha256':sha(r['content'].encode())}
        decision=d=={'status':'VERIFIED','decision':'ALLOW','reason':'EXACT_POLICY_MATCH','scope':scope}
        transition=after==r['content'].encode() and b['execution']=='LOCAL_WRITE_OBSERVED'
        return {'passed':bool(intact and authorized and decision and transition),'integrity':intact,
          'authorization':authorized and decision,'recorded_transition':transition,'external_execution':'UNVERIFIABLE'}
    except (KeyError,ValueError,TypeError,AttributeError,UnicodeError):return {'passed':False,'external_execution':'UNVERIFIABLE'}


if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('input',type=Path);args=a.parse_args();v=json.loads(args.input.read_bytes())
    result=verify(**v);print(json.dumps(result,sort_keys=True));raise SystemExit(not result['passed'])
