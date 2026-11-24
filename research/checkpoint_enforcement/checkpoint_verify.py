"""Independent implementation: no issuer, remote, Guardian or Receipt Gate imports.
Offline crypto with PyNaCl; live challenge read only from operator-selected policy endpoint.
No execution or reconciliation entry point. No Python assert security gates.
"""
import json,hashlib,base64,sqlite3,shutil,secrets,time,urllib.request,sys,tempfile
from pathlib import Path
from contextlib import closing
from nacl.signing import VerifyKey
def require(ok,message):
    if not ok:raise ValueError(message)
def parse(raw):
    def pairs(items):
        d={}
        for k,v in items:require(k not in d,'DUPLICATE_FIELD');d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('NONFINITE')))
def encode(obj):
    # Independent recursive canonical encoder for the ASCII/safe-integer profile.
    if obj is None:return b'null'
    if type(obj) is bool:return b'true' if obj else b'false'
    if type(obj) is int:
        require(abs(obj)<=2**53-1,'INTEGER_RANGE');return str(obj).encode()
    if type(obj) is str:
        obj.encode('ascii');return json.dumps(obj,ensure_ascii=True,separators=(',',':')).encode()
    if type(obj) is list:return b'['+b','.join(encode(v) for v in obj)+b']'
    require(type(obj) is dict and all(type(k) is str for k in obj),'CANONICAL_TYPE')
    return b'{'+b','.join(encode(k)+b':'+encode(obj[k]) for k in sorted(obj))+b'}'
def digest(data):return hashlib.sha256(data).hexdigest()
def h(cp):return digest(b'guardian.checkpoint.v1\x00'+encode(cp))
def signed(cp,key,domain):
    require(set(cp)=={'record','signature'},'ENVELOPE_FIELDS')
    VerifyKey(bytes.fromhex(key)).verify(domain+encode(cp['record']),base64.b64decode(cp['signature'],validate=True))
def chain_valid(chain,policy):
    require(type(chain) is list and 0<len(chain)<=64,'CHAIN_LENGTH')
    keys={'schema','scope','guardian_id','session_id','source_sha','policy_sha256','state_profile','state_digest','recovery_state','journal_head','committed_evidence_head','sequence','previous_checkpoint_head','grant_id','attempt_id','container_id','receipt_sha256','dispatch_sha256','key_id','observation'}
    previous=None;identity=None
    for i,cp in enumerate(chain,1):
        signed(cp,policy['checkpoint_public'],b'guardian.checkpoint.v1\x00');r=cp['record']
        require(set(r)==keys,'CHECKPOINT_FIELDS')
        require(r['schema']=='guardian.checkpoint.v1' and r['scope']=='LAB_OBSERVATION_NOT_AUTHORIZATION','DOMAIN')
        require(r['state_profile'] in ('guardian-sql-logical-ascii-v1','guardian-sql-bootstrap-ascii-v1') and r['observation']=='quiescent-copy-sqlite-read-transaction-backup','SNAPSHOT_PROFILE')
        if r['state_profile']=='guardian-sql-bootstrap-ascii-v1':
            require(i==1 and r['recovery_state']=='EMPTY' and all(r[k] is None for k in ('attempt_id','container_id','receipt_sha256','dispatch_sha256','committed_evidence_head')),'BOOTSTRAP_POSITION')
        require(type(r['sequence']) is int and r['sequence']==i and r['previous_checkpoint_head']==previous,'SIGNED_CHAIN_CONSISTENCY')
        require(r['key_id']==digest(bytes.fromhex(policy['checkpoint_public'])),'KEY_ID')
        require(r['guardian_id']==policy['guardian_id'] and r['session_id']==policy['session_id'],'CHECKPOINT_IDENTITY')
        require(r['source_sha']==policy['source_sha'] and r['policy_sha256']==policy['native_policy_sha256'],'POLICY_SOURCE_BINDING')
        here=[r[k] for k in ('guardian_id','session_id','grant_id','attempt_id','container_id')]
        if identity is not None:
            require(here[:3]==identity[:3] and all(old is None or old==new for old,new in zip(identity[3:],here[3:])),'CROSS_HISTORY_CHAIN')
        identity=here
        previous=h(cp)
    return chain[-1]
def state(root,policy,scratch):
    scratch.mkdir(parents=True,exist_ok=False)
    files=['request.json','grant.json','receipt.json','dispatch.json','outcome.json','stdout.bin','stderr.bin','worker-witness.json','expectations.json']
    paths=list(root.glob('state.sqlite*'))+[root/'policy.json']+[root/'job'/n for n in files]
    before={str(p):digest(p.read_bytes()) for p in paths}
    for f in root.glob('state.sqlite*'):shutil.copy2(f,scratch/f.name)
    with closing(sqlite3.connect((scratch/'state.sqlite').as_uri()+'?mode=ro',uri=True)) as c:
        c.row_factory=sqlite3.Row;c.execute('BEGIN')
        require(c.execute('pragma integrity_check').fetchone()[0]=='ok','SQLITE_INTEGRITY')
        require(c.execute('pragma journal_mode').fetchone()[0]=='wal','WAL_MODE')
        rows=[dict(r) for r in c.execute('select * from unified_admissions order by grant_id')]
        tr=[dict(r) for r in c.execute('select * from unified_transitions order by grant_id,ordinal')]
    require(len(rows)==1,'HISTORY_COUNT');a=rows[0]
    native=policy['native_pins'];job=root/'job';rd=lambda name:parse((job/name).read_bytes())
    g=rd('grant.json');r=rd('receipt.json');q=rd('request.json');d=rd('dispatch.json');o=rd('outcome.json')
    for obj,key in [(g,native['grant_public']),(r,native['receipt_public'])]:
        VerifyKey(bytes.fromhex(key)).verify(encode(obj['payload']),base64.b64decode(obj['signature'],validate=True))
    gp=g['payload'];rp=r['payload']
    bind={k:q[k] for k in ('request_id','operation','agent_id','resource_id','tool','destination','service')};bind['body_sha256']=digest(encode(q['body']))
    require(bind==gp['binding'] and digest(encode(bind))==gp['binding_sha256']==a['binding_sha256']==rp['request_sha256'],'NATIVE_REQUEST_BINDING')
    require(digest((job/'request.json').read_bytes())==native['request_sha256'],'REQUEST_PIN')
    require(digest(encode(g))==a['grant_sha256']==rp['grant_sha256'],'GRANT_BINDING')
    require(a['grant_id']==gp['grant_id']==rp['grant_id']==d['grant_id'] and a['attempt_id']==rp['receipt_id'],'NATIVE_IDENTITY')
    require(a['container_id']==d['container_id']==o['container_id'],'DISPATCH_IDENTITY')
    require(a['owner_session']==policy['session_id'],'SESSION')
    require(digest((job/'stdout.bin').read_bytes())==o['stdout_sha256']==rp['stdout_sha256'],'OUTPUT_BINDING')
    require(digest(encode(o))==rp['outcome_sha256'],'OUTCOME_BINDING')
    expected=['PREPARED','DISPATCH_RECORDED','RESULT_OBSERVED','RECEIPT_PUBLISHED','COMMITTED']
    require(1<=len(tr)<=5 and a['state']==tr[-1]['new_state'],'LIFECYCLE')
    for i,row in enumerate(tr):require(row['ordinal']==i+1 and row['grant_id']==a['grant_id'] and row['new_state']==expected[i] and row['prior_state']==(None if i==0 else expected[i-1]),'TRANSITIONS')
    ev={n:digest((job/n).read_bytes()) for n in files};pol=digest((root/'policy.json').read_bytes())
    require(pol==policy['native_policy_sha256'],'LOCAL_POLICY_CHANGED')
    require(a['receipt_sha256'] is None or a['receipt_sha256']==ev['receipt.json'],'DB_RECEIPT')
    require(before=={str(p):digest(p.read_bytes()) for p in paths},'CHANGED_DURING_READ')
    def normal(row):return {k:str(v) if type(v) is int else v for k,v in row.items()}
    return {'admission':normal(a),'transitions':[normal(v) for v in tr],'evidence':ev,'policy_sha256':pol}
def bootstrap_state(root,policy,scratch):
    """Explicit signed empty-admission state with independently pinned intent.
    Missing evidence is never interpreted as zero; both SQL tables must exist and
    be empty, and exact signed grant/request intent must be available.
    """
    scratch.mkdir(parents=True,exist_ok=False)
    paths=list(root.glob('state.sqlite*'))+[root/'policy.json',root/'intent/request.json',root/'intent/grant.json']
    before={str(p):digest(p.read_bytes()) for p in paths}
    for p in root.glob('state.sqlite*'):shutil.copy2(p,scratch/p.name)
    with closing(sqlite3.connect((scratch/'state.sqlite').as_uri()+'?mode=ro',uri=True)) as c:
        c.execute('BEGIN')
        require(c.execute('pragma integrity_check').fetchone()[0]=='ok','SQLITE_INTEGRITY')
        require(c.execute('pragma journal_mode').fetchone()[0]=='wal','WAL_MODE')
        require(c.execute('select count(*) from unified_admissions').fetchone()[0]==0 and c.execute('select count(*) from unified_transitions').fetchone()[0]==0,'BOOTSTRAP_NOT_EMPTY')
    q=parse((root/'intent/request.json').read_bytes());g=parse((root/'intent/grant.json').read_bytes());native=policy['native_pins']
    VerifyKey(bytes.fromhex(native['grant_public'])).verify(encode(g['payload']),base64.b64decode(g['signature'],validate=True))
    bind={k:q[k] for k in ('request_id','operation','agent_id','resource_id','tool','destination','service')};bind['body_sha256']=digest(encode(q['body']))
    require(bind==g['payload']['binding'] and digest(encode(bind))==g['payload']['binding_sha256'],'BOOTSTRAP_REQUEST_BINDING')
    require(digest((root/'intent/request.json').read_bytes())==native['request_sha256'],'REQUEST_PIN')
    require(q['body']['proposal']['session_id']==policy['session_id'],'SESSION')
    require(digest((root/'policy.json').read_bytes())==policy['native_policy_sha256'],'LOCAL_POLICY_CHANGED')
    require(before=={str(p):digest(p.read_bytes()) for p in paths},'CHANGED_DURING_READ')
    return {'admission':None,'transitions':[],'intent':{'request_sha256':native['request_sha256'],'grant_sha256':digest((root/'intent/grant.json').read_bytes()),'grant_id':g['payload']['grant_id']},'policy_sha256':policy['native_policy_sha256']}

def verify(case,policy,scratch,lab=False):
    result={'status':'HOLD','trusted_latest_head':'NOT_ESTABLISHED','scope':'SYNTHETIC_REMOTE_ONLY','dispatch_allowed':False,'reconciliation_allowed':False,'observations':[]}
    try:
        require(policy['profile']=='guardian.lab-checkpoint-trust.v1' and not policy['revoked'],'TRUST_POLICY')
        require(policy['remote_independence']=='SAME_ADMIN_NOT_ESTABLISHED','UNSUPPORTED_TRUST_CLAIM')
        cp=chain_valid(parse((case/'chain.json').read_bytes()),policy)
        r=cp['record'];bootstrap=r['state_profile']=='guardian-sql-bootstrap-ascii-v1'
        s=bootstrap_state(case/'state',policy,scratch) if bootstrap else state(case/'state',policy,scratch)
        require(digest(encode(s))==r['state_digest'],'STATE_DIGEST_BINDING')
        require(r['journal_head']==digest(encode(s['transitions'])),'STATE_JOURNAL_BINDING')
        if bootstrap:require(r['grant_id']==s['intent']['grant_id'],'BOOTSTRAP_GRANT_BINDING')
        else:
            a=s['admission'];e=s['evidence']
            require(r['recovery_state']==a['state'],'STATE_JOURNAL_BINDING')
            require(r['committed_evidence_head']==(e['receipt.json'] if a['state']=='COMMITTED' else None),'COMMITTED_HEAD_BINDING')
            for field,expected in [('grant_id',a['grant_id']),('attempt_id',a['attempt_id']),('container_id',a['container_id']),('receipt_sha256',e['receipt.json']),('dispatch_sha256',e['dispatch.json'])]:require(r[field]==expected,'STATE_IDENTITY_BINDING')
        heads=[]
        for _ in range(2):
            nonce=secrets.token_hex(32);body=encode({'nonce':nonce});start=time.time()
            req=urllib.request.Request(policy['endpoint'],data=body,headers={'Content-Type':'application/json'},method='POST')
            # Endpoint is selected in external trust policy, never in case/receipt metadata.
            with urllib.request.urlopen(req,timeout=2) as reply:
                raw=reply.read(1024*1024+1);require(len(raw)<=1024*1024,'REMOTE_LIMIT')
            response=parse(raw);result['observations'].append({'requested_nonce':nonce,'observed_at':start,'response':response})
            signed({'record':response['record'],'signature':response['signature']},policy['checkpoint_public'],b'guardian.lab-head-response.v1\x00')
            rr=response['record'];require(rr['schema']=='guardian.lab-head-response.v1' and rr['scope']=='SYNTHETIC_REMOTE_ONLY' and rr['namespace']==policy['guardian_id'],'REMOTE_IDENTITY')
            require(rr['nonce']==nonce and start-5<=rr['issued_at']<=time.time()+2 and time.time()<=rr['expires_at']<=rr['issued_at']+10,'REMOTE_FRESHNESS')
            remote=chain_valid(response['chain'],policy);require(h(remote)==rr['head'] and remote['record']['sequence']==rr['sequence'],'REMOTE_HEAD_BINDING')
            heads.append((rr['sequence'],rr['head'],response['chain']))
        require(heads[0][:2]==heads[1][:2],'REMOTE_EQUIVOCATION')
        seq,head,remotechain=heads[0]
        require(seq>=policy['minimum_sequence'],'REMOTE_BELOW_HIGH_WATER')
        if seq==policy['minimum_sequence']:require(head==policy['minimum_head'],'REMOTE_HIGH_WATER_CONFLICT')
        if r['sequence']<seq:
            require(h(cp)==h(remotechain[r['sequence']-1]),'LOCAL_FORK');result['status']='HOLD_LOCAL_ROLLBACK';return result
        require(r['sequence']==seq and h(cp)==head,'LOCAL_REMOTE_MISMATCH')
        result['status']='CURRENT' if lab else 'LATEST_HEAD_NOT_ESTABLISHED / HOLD'
        result['laboratory_current']=True
        return result
    except Exception as exc:result['reason']=type(exc).__name__+':'+str(exc);return result
if __name__=='__main__':
    case=Path(sys.argv[1]).resolve();policy_path=Path(sys.argv[2]).resolve();out=Path(sys.argv[3]).resolve()
    # Trust configuration is a distinct operator-selected file, outside every mutable case.
    result=verify(case,parse(policy_path.read_bytes()),out.with_suffix('.sql-read'),lab='--lab' in sys.argv)
    result['policy_file_sha256']=digest(policy_path.read_bytes())
    out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps({k:v for k,v in result.items() if k!='observations'}))
