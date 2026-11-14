"""Second-path offline verifier: independent transcript predicates, native exit and OS evidence.

It does not trust a report's PASS flag or its proposed trust root. OS observations
remain local launcher evidence, not externally authenticated machine attestation.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import re
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from research.guardian_mutual_ipc_v1.replay_policy import canonical, load, root_at, admit, capture_authorized

CASES = ("normal", "bad_nonce", "bad_tool", "missing_auth", "bad_signature", "wrong_key", "wrong_session",
         "wrong_challenge", "wrong_request", "wrong_broker", "wrong_root", "wrong_channel", "wrong_version",
         "wrong_phase", "stale", "replay", "final_bad_signature", "final_missing_auth", "final_execution_claim",
         "missing_trust", "revoked_trust", "incorrect_trust_key", "expired_trust", "broker_crash", "outage", "host_spoof", "silent_hello", "silent_result")


def require(ok, reason):
    if not ok: raise ValueError(reason)


CONTEXT = {'protocol','session_id','client_challenge','broker_id','trust_root_version','key_id','channel_id'}


def hello_valid(hello, root, channel):
    require(type(hello) is dict and set(hello) == CONTEXT | {'op','agent_id'}, 'HELLO_SHAPE')
    require(hello['protocol']=='guardian.mutual-ipc-auth.v1' and hello['op']=='HELLO' and hello['agent_id']=='resonance-agent-v5', 'HELLO_VERSION')
    require(all(type(hello[k]) is str and re.fullmatch(r'[0-9a-f]{64}',hello[k]) for k in ('session_id','client_challenge')), 'HELLO_FRESHNESS')
    require(type(channel) is str and re.fullmatch(r'guardian-resonance-[0-9a-f]{24}',channel) and hello['channel_id']==channel, 'HELLO_CHANNEL')
    require(all(hello[k]==root[k] for k in ('broker_id','trust_root_version','key_id')), 'HELLO_AUTHORITY')


def response_failure(e, root, hello, request, phase, now):
    if type(e) is not dict or set(e) != {'payload','signature'}: return 'AUTH_MISSING'
    p=e['payload']
    fields={'protocol','session_id','client_challenge','broker_id','trust_root_version','key_id','channel_id','phase','request_sha256','issued_at','expires_at','response'}
    if type(p) is not dict or set(p)!=fields:return 'AUTH_SHAPE'
    if p['protocol']!='guardian.mutual-ipc-auth.v1':return 'AUTH_VERSION'
    for field,code in [('session_id','AUTH_SESSION'),('client_challenge','AUTH_CHALLENGE'),('channel_id','AUTH_CHANNEL')]:
        if p[field]!=hello[field]:return code
    if any(p[k]!=root[k] for k in ('broker_id','trust_root_version','key_id')):return 'AUTH_AUTHORITY'
    if p['phase']!=phase:return 'AUTH_PHASE'
    if p['request_sha256']!=hashlib.sha256(canonical(request)).hexdigest():return 'AUTH_REQUEST'
    if not (type(p['issued_at']) is int and type(p['expires_at']) is int and 0<p['expires_at']-p['issued_at']<=30 and p['issued_at']<=now<p['expires_at']):return 'AUTH_TIME'
    root_at(root,p['issued_at'])
    if type(e['signature']) is not str or not re.fullmatch(r'[0-9a-f]{128}',e['signature']):return 'AUTH_SIGNATURE_SHAPE'
    try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(root['public_key'])).verify(bytes.fromhex(e['signature']),b'GUARDIAN-BROKER-AUTH-V1\x00'+canonical(p))
    except (InvalidSignature,ValueError,TypeError):return 'AUTH_SIGNATURE'
    value=p['response']
    if phase=='hello':
        if type(value) is not dict or set(value)!={'verdict','nonce','observations_scaled','scale','tools_enabled'}:return 'RESPONSE_SHAPE'
        if type(value['nonce']) is not str or not re.fullmatch(r'[0-9a-f]{64}',value['nonce']):return 'RESPONSE_SIGNALS'
        if type(value['scale']) is not int or type(value['observations_scaled']) is not list or any(type(x) is not int for x in value['observations_scaled']):return 'RESPONSE_SIGNALS'
        if value['verdict']!='SYNTHETIC_OBSERVATIONS' or value['tools_enabled'] is not False or value['scale']!=100 or value['observations_scaled']!=[20,30,40]:return 'RESPONSE_SIGNALS'
    else:
        if type(value) is not dict or set(value)!={'verdict','grant_issued','tool_executed'}:return 'RESPONSE_SHAPE'
        if value['verdict'] not in ('HOLD_GUARDIAN_GRANT_REQUIRED','DENY_REQUEST_OR_NONCE') or value['grant_issued'] is not False or value['tool_executed'] is not False:return 'RESPONSE_NOT_HOLD'
    return None


def verify_case(case,r,root):
    # Low-level transcript checks establish historical consistency only. Authority
    # is admitted separately by assess using independently pinned policy evidence.
    canonical(r)
    root_at(root,r['finished_at'])
    require(r['case']==case and r['schema']=='guardian.mutual-native-case.v1' and r['status']=='OBSERVED','CASE_NOT_OBSERVED')
    require(r['trust']==root,'TRUST_SUBSTITUTION')
    require(all(r[k] is False for k in ('production_ready','grant_issued','tool_executed','global_runtime_acl_changed')),'SCOPE')
    require(r['temporary_root_deleted'] is True,'CLEANUP')
    if case=='host_spoof':
        require(r['host_reply']=={'verdict':'DENY_CLIENT_IDENTITY'} and r['broker']['verdict']=='DENY_CLIENT_IDENTITY','HOST_SPOOF')
        require(r['broker']['client_identity']['appcontainer'] is False,'HOST_IDENTITY')
        return 'UNCONFINED_CLIENT_REFUSED'
    t=r['client_token']
    require(t['appcontainer'] is True and t['capability_count']==0 and t['elevated'] is False and t['integrity_sid']=='S-1-16-4096','TOKEN')
    require(hashlib.sha256(t['appcontainer_sid'].encode()).hexdigest()==r['expected_sid_sha256'],'TOKEN_SID')
    if case in ('missing_trust','revoked_trust','expired_trust'):
        require(r['client_exit']==89 and 'broker' not in r,'TRUST_REFUSAL')
        if case=='missing_trust':require(r['configured_trust'] is None,'TRUST_MISSING')
        if case=='revoked_trust':require(r['configured_trust']['revoked'] is True,'REVOCATION')
        if case=='expired_trust':require(r['configured_trust']['expires_at']<r['finished_at'],'EXPIRY')
        return 'TRUST_REFUSED_BEFORE_CONNECT'
    if case=='outage':
        require(r['client_exit']==86 and 'broker' not in r,'OUTAGE')
        return 'UNAVAILABLE_REFUSED'
    b=r['broker'];ident=b['client_identity']
    require(ident['appcontainer'] is True and ident['capability_count']==0 and ident['sid_sha256']==r['expected_sid_sha256'],'BROKER_CLIENT_IDENTITY')
    require(b['grant_issued'] is False and b['tool_executed'] is False and b['production_ready'] is False,'BROKER_SCOPE')
    if case in ('silent_hello','silent_result'):
        diag=r['client_io'];events=diag['io']
        require(r['client_exit']==91 and diag['exit']==91 and 2500<=r['client_wall_ms']<10000,'IO_DEADLINE')
        require(events[0]['client_pid']==r['client_pid'] and events[0]['broker_pid']==b['broker_pid'] and events[0]['identity_authority'] is False,'OS_PID_OBSERVATION')
        cancelled=[e for e in events if e.get('deadline_refused') is True]
        require(len(cancelled)==1 and cancelled[0]['cancel_requested'] is True and cancelled[0]['completion_wait']==0 and cancelled[0]['completion_error']==995,'IO_CANCELLATION')
        require(2500<=cancelled[0]['elapsed_ms']<5000,'IO_CANCELLATION_BOUND')
        require(len(events)==(3 if case=='silent_hello' else 5),'IO_PHASE')
        return 'LOCAL_IO_DEADLINE_CANCELLED'
    if case=='broker_crash':
        require(r['client_exit']==87 and b['verdict']=='CONTROL_BROKEN' and b.get('reason')=='SYNTHETIC_BROKER_CRASH','CRASH_REFUSAL')
        return 'CRASHED_BROKER_TRANSPORT_REFUSED'
    transcript=b['transcript'];require(len(transcript) in (1,2),'TRANSCRIPT_LENGTH')
    hello=transcript[0]['request']
    hello_valid(hello,root,r['channel_id'])
    selected=r['configured_trust']
    if case!='incorrect_trust_key':require(selected==root,'CONFIGURED_TRUST')
    else:require(selected['public_key']!=root['public_key'] and all(selected[k]==root[k] for k in root if k!='public_key'),'INCORRECT_KEY_CONTROL')
    reasons=[response_failure(row['reply'],selected,hello,row['request'],'hello' if i==0 else 'result',r['finished_at']) for i,row in enumerate(transcript)]
    if case in ('normal','bad_nonce','bad_tool'):
        require(reasons==[None,None],'AUTH_POSITIVE')
        proposal=transcript[1]['request'];nonce=transcript[0]['reply']['payload']['response']['nonce']
        expected_proposal={**{k:hello[k] for k in CONTEXT},'op':'PROPOSE_TOOL','agent_id':'resonance-agent-v5',
            'nonce':'0'*64 if case=='bad_nonce' else nonce,'tool':'shell' if case=='bad_tool' else 'resonance.synthetic-hash-only.v0',
            'resource_id':'resonance-synthetic-observation-v0','decision':'OBSERVE','ticks':3,'docker_errors':{'linux':5,'legacy':5}}
        require(canonical(proposal)==canonical(expected_proposal),'PROPOSAL_BINDING')
        require(proposal['docker_errors']=={'linux':5,'legacy':5} and proposal['ticks']==3 and proposal['decision']=='OBSERVE','CORE_OR_PIPE_BOUNDARY')
        require(proposal['nonce']==('0'*64 if case=='bad_nonce' else nonce),'NONCE')
        require(proposal['tool']==('shell' if case=='bad_tool' else 'resonance.synthetic-hash-only.v0'),'TOOL')
        expected='HOLD_GUARDIAN_GRANT_REQUIRED' if case=='normal' else 'DENY_REQUEST_OR_NONCE'
        code=73 if case=='normal' else 75
        require(r['client_exit']==code and b['client_result']=={'op':'CLIENT_RESULT','code':code,'reason':expected} and transcript[1]['reply']['payload']['response']['verdict']==expected,'TERMINAL_HOLD_OR_DENY')
        return expected
    expected_reasons={'missing_auth':'AUTH_MISSING','bad_signature':'AUTH_SIGNATURE','wrong_key':'AUTH_SIGNATURE','wrong_session':'AUTH_SESSION',
        'wrong_challenge':'AUTH_CHALLENGE','wrong_request':'AUTH_REQUEST','wrong_broker':'AUTH_AUTHORITY','wrong_root':'AUTH_AUTHORITY',
        'wrong_channel':'AUTH_CHANNEL','wrong_version':'AUTH_VERSION','wrong_phase':'AUTH_PHASE','stale':'AUTH_TIME','replay':'AUTH_SESSION',
        'final_bad_signature':'AUTH_SIGNATURE','final_missing_auth':'AUTH_MISSING','final_execution_claim':'RESPONSE_NOT_HOLD','incorrect_trust_key':'AUTH_SIGNATURE'}
    expected=expected_reasons[case]
    require(reasons==([None,expected] if case.startswith('final_') else [expected]),'WRONG_REFUSAL_BOUNDARY')
    require(r['client_exit']==88 and b['client_result']=={'op':'CLIENT_RESULT','code':88,'reason':expected},'CLIENT_REFUSAL')
    return expected


def assess(folder,pin,policy_path,policy_pin,minimum_policy_epoch,minimum_trust_epoch,now=None,suite='repair-v1'):
    raw=(folder/'trust.json').read_bytes();require(hashlib.sha256(raw).hexdigest()==pin,'INDEPENDENT_TRUST_PIN')
    root=load(raw);rows={};errors={}
    policy_raw=Path(policy_path).read_bytes()
    require(hashlib.sha256(policy_raw).hexdigest()==policy_pin,'INDEPENDENT_POLICY_PIN')
    policy=admit(load(policy_raw),root,pin,now=int(time.time()) if now is None else now,
        minimum_policy_epoch=minimum_policy_epoch,minimum_trust_epoch=minimum_trust_epoch)
    require(suite in ('original-v1','repair-v1'),'EVIDENCE_SUITE')
    cases=CASES if suite=='repair-v1' else CASES[:-2]
    for case in cases:
        try:
            record=load((folder/(case+'.json')).read_bytes())
            capture_authorized(policy,root,record['finished_at'])
            rows[case]=verify_case(case,record,root)
        except (OSError,ValueError,KeyError,TypeError) as e:errors[case]=str(e)
    return {'schema':'guardian.mutual-independent-result.v1','suite':suite,'cases':rows,'errors':errors,'passed':len(rows)==len(cases) and not errors,
            'verification_mode':policy['mode'],'current_authorization':'ROOT_ADMITTED_ONLY' if policy['mode']=='current' else 'NOT_ESTABLISHED',
            'process_identity':'NOT_ESTABLISHED_BY_SIGNATURE','policy_sha256':policy_pin,
            'production_ready':False,'grant_issued':False,'tool_executed':False,'trust_sha256':pin}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--trust-sha256',required=True)
    p.add_argument('--policy',type=Path,required=True);p.add_argument('--policy-sha256',required=True)
    p.add_argument('--minimum-policy-epoch',type=int,required=True);p.add_argument('--minimum-trust-epoch',type=int,required=True)
    p.add_argument('--suite',choices=('original-v1','repair-v1'),default='repair-v1')
    a=p.parse_args()
    try:r=assess(a.evidence,a.trust_sha256,a.policy,a.policy_sha256,a.minimum_policy_epoch,a.minimum_trust_epoch,suite=a.suite)
    except (OSError,ValueError,KeyError,TypeError) as e:r={'passed':False,'error':str(e),'production_ready':False}
    print(json.dumps(r,sort_keys=True,separators=(',',':')))
    raise SystemExit(0 if r['passed'] else 1)
