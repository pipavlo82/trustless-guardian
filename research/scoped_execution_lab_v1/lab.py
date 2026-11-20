"""Trusted-host laboratory composition of live SID authentication and v2 grants.

No network service. Caller is a trusted local supervisor, not an agent-facing API.
Neither historical evidence files nor a signed transcript alone authorize jobs.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.auth_gateway_v1.canonical import canonical_json_bytes as canonical
from research.auth_gateway_v1.errors import SecurityError
from research.auth_gateway_v1.model import RequestBinding, AuthenticatedPrincipal
from research.replay_challenge_v1.scoped_grant import issue_scoped_execution_grant, verify_scoped_execution_grant
from research.replay_challenge_v1.receipt import issue_execution_receipt

HERE = Path(__file__).resolve().parent
IMAGE_PIN = json.loads((HERE/'image.json').read_bytes())
IMAGE = IMAGE_PIN['image']
SCOPE = 'guardian.synthetic-hash.lab.v1'
TRUST = 'ephemeral-local-lab-v1'
WORKER = HERE / 'worker'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def require(ok, reason):
    if not ok:
        raise SecurityError(reason)

def policy_admit(policy, sid, now):
    require(type(policy) is dict and set(policy) == {'schema','enabled','revoked','sid','epoch','not_before','expires_at'}, 'LAB_POLICY_SHAPE')
    require(policy['schema'] == 'guardian.synthetic-policy.v1' and policy['enabled'] is True and policy['revoked'] is False, 'LAB_POLICY_REFUSED')
    require(policy['sid'] == sid and type(sid) is str and sid.startswith('S-1-15-2-'), 'LAB_POLICY_SID')
    require(type(policy['epoch']) is int and policy['epoch'] == 1, 'LAB_POLICY_EPOCH')
    require(type(now) is int and type(policy['not_before']) is int and type(policy['expires_at']) is int and policy['not_before'] <= now < policy['expires_at'] and policy['expires_at']-policy['not_before'] <= 120, 'LAB_POLICY_TIME')

def admit_live_result(result, sid, policy, now):
    """ONLY for result returned directly by broker.serve in this same process.

    A Python dict cannot attest its provenance. This API is inside the trusted
    host boundary, and intentionally is not exported as an MCP/HTTP endpoint.
    """
    policy_admit(policy, sid, now)
    ident = result.get('client_identity', {})
    require(ident.get('appcontainer') is True and ident.get('capability_count') == 0 and type(ident.get('capability_count')) is int and ident.get('appcontainer_sid') == sid, 'LAB_CLIENT_IDENTITY')
    require(result.get('verdict') == 'HOLD_GUARDIAN_GRANT_REQUIRED' and result.get('client_result') == {'op':'CLIENT_RESULT','code':73,'reason':'HOLD_GUARDIAN_GRANT_REQUIRED'}, 'LAB_IPC_NOT_COMPLETE')
    rows = result.get('transcript', [])
    require(len(rows) == 2, 'LAB_TRANSCRIPT')
    proposal = rows[1]['request']
    require(proposal.get('agent_id') == 'resonance-agent-v5' and proposal.get('tool') == 'resonance.synthetic-hash-only.v0' and proposal.get('resource_id') == 'resonance-synthetic-observation-v0', 'LAB_TOOL_SCOPE')
    return {'schema':'guardian.authenticated-request.v1','request_id':'lab-'+proposal['session_id'],
            'operation':'RUN_TOOL','agent_id':proposal['agent_id'],'resource_id':'synthetic-request-hash',
            'tool':'synthetic_request_hash','destination':'docker://disposable/tmp/guardian-action','service':'LOCAL_LAB',
            'body':{'proposal':proposal,'native_transcript_sha256':sha(canonical(rows)),'policy_sha256':sha(canonical(policy))}}

def issue(request, key, sid, now):
    principal = AuthenticatedPrincipal(sid, 'LAB_SYNTHETIC', '', 'WINDOWS_PIPE_SID', 'live-session', TRUST)
    return issue_scoped_execution_grant(key, RequestBinding.from_request(request), principal, TRUST, SCOPE,
                                       sha(WORKER.read_bytes()), IMAGE, now, 'lab-grant-'+secrets.token_hex(16))

def docker(argv, timeout=15):
    return subprocess.run(['docker', *argv], capture_output=True, timeout=timeout,
                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))

def execute(request, grant, grant_public, receipt_key, state, policy, sid, now, out, *, deadline=15):
    """No caller-controlled image, worker, command, path, environment, or mounts."""
    out = Path(out); out.mkdir(parents=True, exist_ok=False)
    launches = 0
    try:
        policy_admit(policy, sid, now)
        require(sha(WORKER.read_bytes()) == IMAGE_PIN['worker_sha256'], 'LAB_WORKER_BYTES')
        binding = RequestBinding.from_request(request)
        require(request['body'].get('policy_sha256') == sha(canonical(policy)), 'LAB_POLICY_BINDING')
        require(binding.agent_id == 'resonance-agent-v5' and binding.operation == 'RUN_TOOL' and binding.tool == 'synthetic_request_hash' and binding.resource_id == 'synthetic-request-hash' and binding.destination == 'docker://disposable/tmp/guardian-action' and binding.service == 'LOCAL_LAB', 'LAB_ACTION_SCOPE')
        payload, grant_hash = verify_scoped_execution_grant(grant, grant_public, now, SCOPE, binding, sha(WORKER.read_bytes()), IMAGE, TRUST)
        require(payload['subject'] == sid and payload['role'] == 'LAB_SYNTHETIC', 'LAB_SUBJECT')
        claim = state.prepare_admission(payload['grant_id'], grant_hash, binding.digest(), request['body']['proposal']['session_id'],
                                        'attempt-'+secrets.token_hex(16), now, payload['expires_at'])
    except (SecurityError, KeyError, TypeError, ValueError) as error:
        return {'status':'REFUSED','reason':getattr(error,'code','MALFORMED_INPUT'),'launches':0}
    name = 'guardian-scoped-lab-'+secrets.token_hex(12)
    stdout = b''; stderr = b''; timed_out = False; launch_error = None; exit_code = None; inspection = None
    with tempfile.TemporaryDirectory(prefix='guardian-scoped-job-') as temp:
        source = Path(temp)
        (source/'request.json').write_bytes(canonical(request)+b'\n')
        args = ['create','--name',name,'--pull','never','--network','none','--read-only','--cap-drop','ALL',
                '--security-opt','no-new-privileges','--pids-limit','16','--memory','64m','--memory-swap','64m',
                '--cpus','0.5','--user','65534:65534','--ulimit','nofile=64:64',
                '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=8m','--volume',str(source.resolve())+':/input:ro',
                '--entrypoint','/worker',IMAGE]
        created = False; started = False
        try:
            p = docker(args)
            require(p.returncode == 0, 'WORKER_CREATE_FAILED')
            created = True
            p = docker(['inspect',name]); require(p.returncode == 0, 'INSPECT_FAILED')
            inspection = json.loads(p.stdout)[0]
            h = inspection['HostConfig']; c = inspection['Config']
            require(inspection['Image'] == IMAGE and h['NetworkMode']=='none' and h['ReadonlyRootfs'] is True and h['Privileged'] is False and h['CapDrop']==['ALL'] and 'no-new-privileges' in h['SecurityOpt'] and c['User']=='65534:65534' and h['PidsLimit']==16 and h['Memory']==67108864 and h['MemorySwap']==67108864 and h['NanoCpus']==500000000, 'WORKER_ISOLATION')
            require(len(inspection['Mounts']) == 1 and inspection['Mounts'][0]['Destination']=='/input' and inspection['Mounts'][0]['RW'] is False, 'WORKER_MOUNT')
            launch_time = int(time.time())
            policy_admit(policy, sid, launch_time)
            verify_scoped_execution_grant(grant, grant_public, launch_time, SCOPE, binding, sha(WORKER.read_bytes()), IMAGE, TRUST)
            # Fixed source and bounded shell output; run to files, never buffer arbitrary output in RAM.
            with (out/'stdout.bin').open('wb') as so, (out/'stderr.bin').open('wb') as se:
                proc = subprocess.Popen(['docker','start','-a',name],stdout=so,stderr=se,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                launches += 1; started = True
                limit = time.monotonic()+deadline
                while proc.poll() is None:
                    if time.monotonic() >= limit or os.fstat(so.fileno()).st_size+os.fstat(se.fileno()).st_size>65536:
                        timed_out=True
                        docker(['kill',name])
                        try: proc.wait(timeout=5)
                        except subprocess.TimeoutExpired: proc.kill();proc.wait(timeout=5)
                        break
                    time.sleep(.02)
                exit_code = None if timed_out else proc.returncode
            stdout=(out/'stdout.bin').read_bytes();stderr=(out/'stderr.bin').read_bytes()
        except (OSError, ValueError, SecurityError, subprocess.TimeoutExpired) as error:
            launch_error = getattr(error,'code',type(error).__name__)
        finally:
            if created:
                removed=docker(['rm','-f',name]); absent=docker(['inspect',name])
                cleanup=removed.returncode==0 and absent.returncode!=0
            else: cleanup=True
    lifecycle = 'RECOVERY_REQUIRED' if timed_out or launch_error or not started or not cleanup else 'COMMITTED'
    outcome={'container_started':started,'exit_code':exit_code,'timed_out':timed_out,'launch_error':launch_error,
             'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr),'container_name':name,'cleanup':cleanup}
    oh=sha(canonical(outcome))
    if lifecycle=='COMMITTED':state.mark_committed(claim,now,oh,exit_code)
    else:state.mark_recovery_required(claim,now,oh)
    receipt=issue_execution_receipt(receipt_key,claim,grant,grant_hash,payload,lifecycle,now,started,outcome,oh)
    expected={'action':'synthetic_request_hash','request_file_sha256':sha(canonical(request)+b'\n'),'uid':65534}
    expected_bytes=canonical(expected)+b'\n'
    success=lifecycle=='COMMITTED' and exit_code==0 and stdout==expected_bytes and stderr==b''
    artifacts={'request':request,'grant':grant,'receipt':receipt,'outcome':outcome,'inspection':inspection,
               'expectations':{'schema':'guardian.lab-expectations.v1','scope':SCOPE,'trust_version':TRUST,'image':IMAGE,
                  'worker_sha256':sha(WORKER.read_bytes()),'request':request,'sid':sid,'grant_public':grant_public.public_bytes_raw().hex(),
                  'receipt_public':receipt_key.public_key().public_bytes_raw().hex(),'policy':policy}}
    for k,v in artifacts.items():(out/(k+'.json')).write_bytes(canonical(v)+b'\n')
    (out/'stdout.bin').write_bytes(stdout);(out/'stderr.bin').write_bytes(stderr)
    return {'status':'OBSERVED_SYNTHETIC_RESULT' if success else 'UNKNOWN','launches':launches,'cleanup':cleanup,'lifecycle':lifecycle,
            'reason':launch_error,'timed_out':timed_out,'exit_code':exit_code}
