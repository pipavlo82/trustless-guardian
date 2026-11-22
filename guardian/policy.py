"""Versioned finite authorization policy. Caller decisions have no authority."""
import hashlib
import json

FIELDS = {'schema','actor','action','resource','scope','policy_version','expires_at','nonce','content','evidence'}
POLICY_FIELDS = {'schema','version','actors','action','resource','scope','max_bytes','max_ttl','content_prefix'}


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def digest(raw):return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('duplicate key')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))


def evaluate(request,policy,principal,now,before_sha256,used_nonces):
    def deny(reason,status='REFUTED'):return {'status':status,'decision':'DENY','reason':reason,'scope':None}
    if not isinstance(policy,dict) or set(policy)!=POLICY_FIELDS or policy['schema']!='guardian.policy.v0':return deny('POLICY_UNSUPPORTED','UNVERIFIABLE')
    if not isinstance(request,dict) or set(request)!=FIELDS or request.get('schema')!='guardian.action.v0':return deny('REQUEST_SHAPE')
    if request['actor']!=principal or principal not in policy['actors']:return deny('ACTOR')  # GUARD actor
    if request['action']!=policy['action'] or request['action']!='replace_utf8':return deny('ACTION')  # GUARD action
    if request['resource']!=policy['resource']:return deny('RESOURCE')  # GUARD resource
    if request['scope']!=policy['scope']:return deny('SCOPE')  # GUARD scope
    if request['policy_version']!=policy['version']:return deny('POLICY_VERSION')  # GUARD version
    if type(now)!=int or type(request['expires_at'])!=int or not now<=request['expires_at']<=now+policy['max_ttl']:return deny('EXPIRY')  # GUARD expiry
    if not isinstance(request['nonce'],str) or not 1<=len(request['nonce'])<=64 or request['nonce'] in used_nonces:return deny('REPLAY')  # GUARD replay
    evidence=request['evidence']
    if not isinstance(evidence,dict) or set(evidence)!={'before_sha256'}:return deny('EVIDENCE_MISSING','UNVERIFIABLE')  # GUARD evidence
    if evidence['before_sha256']!=before_sha256:return deny('PRECONDITION')  # GUARD precondition
    content=request['content']
    if not isinstance(content,str) or len(content.encode('utf-8'))>policy['max_bytes'] or not content.startswith(policy['content_prefix']):return deny('CONTENT')  # GUARD content
    return {'status':'VERIFIED','decision':'ALLOW','reason':'EXACT_POLICY_MATCH',
            'scope':{'actor':principal,'action':request['action'],'resource':request['resource'],'scope':request['scope'],
                     'policy_version':policy['version'],'expires_at':request['expires_at'],'nonce':request['nonce'],
                     'content_sha256':digest(content.encode('utf-8'))}}
