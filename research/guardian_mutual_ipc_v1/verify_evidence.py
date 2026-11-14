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

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

CASES = ("normal", "bad_nonce", "bad_tool", "missing_auth", "bad_signature", "wrong_key", "wrong_session",
         "wrong_challenge", "wrong_request", "wrong_broker", "wrong_root", "wrong_channel", "wrong_version",
         "wrong_phase", "stale", "replay", "final_bad_signature", "final_missing_auth", "final_execution_claim",
         "missing_trust", "revoked_trust", "incorrect_trust_key", "expired_trust", "broker_crash", "outage", "host_spoof")


def require(ok, reason):
    if not ok: raise ValueError(reason)


def canonical(v): return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode('ascii')


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
    try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(root['public_key'])).verify(bytes.fromhex(e['signature']),b'GUARDIAN-BROKER-AUTH-V1\x00'+canonical(p))
    except (InvalidSignature,ValueError,TypeError):return 'AUTH_SIGNATURE'
    value=p['response']
    if phase=='hello':
        if type(value) is not dict or set(value)!={'verdict','nonce','observations_scaled','scale','tools_enabled'}:return 'RESPONSE_SHAPE'
        if value['verdict']!='SYNTHETIC_OBSERVATIONS' or value['tools_enabled'] is not False or value['scale']!=100 or value['observations_scaled']!=[20,30,40]:return 'RESPONSE_SIGNALS'
    else:
        if type(value) is not dict or set(value)!={'verdict','grant_issued','tool_executed'}:return 'RESPONSE_SHAPE'
        if value['verdict'] not in ('HOLD_GUARDIAN_GRANT_REQUIRED','DENY_REQUEST_OR_NONCE') or value['grant_issued'] is not False or value['tool_executed'] is not False:return 'RESPONSE_NOT_HOLD'
    return None


def verify_case(case,r,root):
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
    if case=='broker_crash':
        require(r['client_exit']==87 and b['verdict']=='CONTROL_BROKEN' and b.get('reason')=='SYNTHETIC_BROKER_CRASH','CRASH_REFUSAL')
        return 'CRASHED_BROKER_TRANSPORT_REFUSED'
    transcript=b['transcript'];require(len(transcript) in (1,2),'TRANSCRIPT_LENGTH')
    hello=transcript[0]['request']
    require(hello['channel_id']==r['channel_id'] and hello['op']=='HELLO','HELLO_CHANNEL')
    selected=r['configured_trust']
    if case!='incorrect_trust_key':require(selected==root,'CONFIGURED_TRUST')
    else:require(selected['public_key']!=root['public_key'] and all(selected[k]==root[k] for k in root if k!='public_key'),'INCORRECT_KEY_CONTROL')
    reasons=[response_failure(row['reply'],selected,hello,row['request'],'hello' if i==0 else 'result',r['finished_at']) for i,row in enumerate(transcript)]
    if case in ('normal','bad_nonce','bad_tool'):
        require(reasons==[None,None],'AUTH_POSITIVE')
        proposal=transcript[1]['request'];nonce=transcript[0]['reply']['payload']['response']['nonce']
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


def assess(folder,pin):
    raw=(folder/'trust.json').read_bytes();require(hashlib.sha256(raw).hexdigest()==pin,'INDEPENDENT_TRUST_PIN')
    root=json.loads(raw);rows={};errors={}
    for case in CASES:
        try:rows[case]=verify_case(case,json.loads((folder/(case+'.json')).read_bytes()),root)
        except (OSError,ValueError,KeyError,TypeError) as e:errors[case]=str(e)
    return {'schema':'guardian.mutual-independent-result.v1','cases':rows,'errors':errors,'passed':len(rows)==len(CASES) and not errors,
            'production_ready':False,'grant_issued':False,'tool_executed':False,'trust_sha256':pin}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--trust-sha256',required=True)
    a=p.parse_args();r=assess(a.evidence,a.trust_sha256);print(json.dumps(r,sort_keys=True,separators=(',',':')))
    raise SystemExit(0 if r['passed'] else 1)
