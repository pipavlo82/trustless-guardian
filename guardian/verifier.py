"""Separate-process audit oracle. Does not import the policy engine or broker."""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def sha(x):return hashlib.sha256(x).hexdigest()


def verify(record,trusted_policy_sha256,expected_head):
    try:
        b=record['body'];r=b['request'];p=b['policy']
        integrity=(set(record)=={'schema','previous','body','sha256'} and record['schema']=='guardian.evidence.v0' and
          record['sha256']==expected_head==sha(canon({'previous':record['previous'],'body':b})) and
          b['request_sha256']==sha(canon(r)) and b['policy_sha256']==sha(canon(p)))
        before=base64.b64decode(b['before_base64'],validate=True);after=base64.b64decode(b['after_base64'],validate=True)
        integrity=integrity and sha(before)==b['before_sha256'] and sha(after)==b['after_sha256']
        fields={'schema','actor','action','resource','scope','policy_version','expires_at','nonce','content','evidence'}
        reason='EXACT_POLICY_MATCH';status='VERIFIED'
        if set(r)!=fields or r['schema']!='guardian.action.v0':reason='REQUEST_SHAPE'
        elif r['actor']!=b['principal'] or b['principal'] not in p['actors']:reason='ACTOR'
        elif r['action']!=p['action'] or r['action']!='replace_utf8':reason='ACTION'
        elif r['resource']!=p['resource']:reason='RESOURCE'
        elif r['scope']!=p['scope']:reason='SCOPE'
        elif r['policy_version']!=p['version']:reason='POLICY_VERSION'
        elif type(r['expires_at'])!=int or not b['verification_time']<=r['expires_at']<=b['verification_time']+p['max_ttl']:reason='EXPIRY'
        elif not isinstance(r['nonce'],str) or not 1<=len(r['nonce'])<=64 or r['nonce'] in b['used_nonces']:reason='REPLAY'
        elif not isinstance(r['evidence'],dict) or set(r['evidence'])!={'before_sha256'}:reason='EVIDENCE_MISSING';status='UNVERIFIABLE'
        elif r['evidence']['before_sha256']!=sha(before):reason='PRECONDITION'
        elif not isinstance(r['content'],str) or len(r['content'].encode())>p['max_bytes'] or not r['content'].startswith(p['content_prefix']):reason='CONTENT'
        if b['policy_sha256']!=trusted_policy_sha256:reason='POLICY_CHANGED';status='REFUTED'
        if b['resource_identity']!=b['trusted_resource_identity']:reason='RESOURCE_IDENTITY';status='REFUTED'
        allowed=reason=='EXACT_POLICY_MATCH'
        if not allowed and status=='VERIFIED':status='REFUTED'
        scope={'actor':b['principal'],'action':r['action'],'resource':r['resource'],'scope':r['scope'],
               'policy_version':p['version'],'expires_at':r['expires_at'],'nonce':r['nonce'],
               'content_sha256':sha(r['content'].encode())} if allowed else None
        decision_ok=b['decision']=={'decision':'ALLOW' if allowed else 'DENY','reason':reason,'status':status,'scope':scope}
        bytes_ok=(after==r['content'].encode() and b['broker_result']=='EXECUTED') if allowed else (after==before and b['broker_result']=='NOT_EXECUTED')
        return {'integrity':'VERIFIED' if integrity else 'REFUTED','decision':'VERIFIED' if decision_ok else 'REFUTED',
          'recorded_transition':'VERIFIED' if bytes_ok else 'REFUTED','external_execution':'UNVERIFIABLE',
          'passed':bool(integrity and decision_ok and bytes_ok)}
    except (KeyError,ValueError,TypeError,AttributeError):return {'passed':False,'integrity':'UNVERIFIABLE','external_execution':'UNVERIFIABLE'}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('record',type=Path);p.add_argument('--policy-sha256',required=True);p.add_argument('--head',required=True)
    args=p.parse_args();result=verify(json.loads(args.record.read_bytes()),args.policy_sha256,args.head)
    print(json.dumps(result,sort_keys=True));raise SystemExit(not result['passed'])
