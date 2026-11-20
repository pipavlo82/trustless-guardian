// Independent captured-evidence replay. OS observations are not hardware attestation.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';
import {canon,verify} from './verify.mjs';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const need=(v,r)=>{if(!v)throw Error(r);};
try {
  const dir=process.argv[2],pin=process.argv[3];
  const raw=fs.readFileSync(path.join(dir,'trust.json'));need(sha(raw)===pin,'BROKER_ROOT_PIN');const trust=JSON.parse(raw);
  const load=n=>JSON.parse(fs.readFileSync(path.join(dir,n+'.json')));
  const b=load('broker'),n=load('native'),e=load('job/expectations'),r=e.request;
  need(trust.revoked===false && trust.not_before<=n.started_at && n.finished_at<trust.expires_at,'ROOT_AT_CAPTURE');
  need(n.status==='OBSERVED' && n.temporary_root_deleted===true && n.client.exit_code===73 && n.broker_exit===0,'NATIVE_COMPLETION');
  need(n.protected_probe.process.exit_code===0 && n.protected_probe.access.rb===5 && n.protected_probe.access.wb===5 && n.protected_probe.unchanged===true,'PROTECTED_RESOURCE');
  const t=n.client.token,i=b.client_identity;
  need(t.appcontainer===true && t.capability_count===0 && t.elevated===false && t.integrity_sid==='S-1-16-4096','CLIENT_TOKEN');
  need(t.appcontainer_sid===n.appcontainer_sid && i.appcontainer===true && i.capability_count===0 && i.appcontainer_sid===t.appcontainer_sid && b.expected_client_sid===t.appcontainer_sid && e.sid===t.appcontainer_sid,'CLIENT_SID');
  need(b.pipe_sddl.includes('(A;;GRGW;;;'+t.appcontainer_sid+')') && b.pipe_sddl.startsWith('D:P'),'PIPE_ACL');
  need(n.client_io.io[0].broker_pid===b.broker_pid && n.client_io.io[0].client_pid===n.client.pid,'OBSERVED_PROCESS_IDS');
  need(b.verdict==='HOLD_GUARDIAN_GRANT_REQUIRED' && b.grant_issued===false && b.tool_executed===false,'LEGACY_HOLD');
  need(b.transcript.length===2,'TRANSCRIPT_COUNT');
  const key=crypto.createPublicKey({key:Buffer.from('302a300506032b6570032100'+trust.public_key,'hex'),format:'der',type:'spki'});
  const hello=b.transcript[0].request;
  for(const [idx,row] of b.transcript.entries()){
    const p=row.reply.payload,sig=row.reply.signature;
    need(/^[0-9a-f]{128}$/.test(sig) && crypto.verify(null,Buffer.concat([Buffer.from('GUARDIAN-BROKER-AUTH-V1\0'),Buffer.from(canon(p))]),key,Buffer.from(sig,'hex')),'BROKER_SIGNATURE');
    need(p.protocol==='guardian.mutual-ipc-auth.v1'&&p.phase===(idx?'result':'hello'),'PROTOCOL');
    for(const k of ['session_id','client_challenge','channel_id','broker_id','key_id','trust_root_version'])need(p[k]===hello[k],'CONTEXT');
    for(const k of ['broker_id','key_id','trust_root_version'])need(p[k]===trust[k],'BROKER_IDENTITY');
    need(p.request_sha256===sha(canon(row.request)),'SIGNED_REQUEST');
    need(Number.isSafeInteger(p.issued_at)&&Number.isSafeInteger(p.expires_at)&&p.issued_at<=n.finished_at&&n.finished_at<p.expires_at&&p.expires_at-p.issued_at<=30,'SIGNED_TIME');
  }
  const proposal=b.transcript[1].request;
  need(proposal.nonce===b.transcript[0].reply.payload.response.nonce && /^[a-f0-9]{64}$/.test(proposal.nonce),'NONCE');
  need(proposal.agent_id==='resonance-agent-v5' && proposal.tool==='resonance.synthetic-hash-only.v0','REQUEST_SCOPE');
  need(proposal.resource_id==='resonance-synthetic-observation-v0' && proposal.decision==='OBSERVE' && proposal.ticks===3 && canon(proposal.docker_errors)===canon({legacy:5,linux:5}),'AGENT_DIRECT_DOCKER_REFUSED');
  need(r.body.native_transcript_sha256===sha(canon(b.transcript)) && canon(r.body.proposal)===canon(proposal),'NATIVE_TO_GRANT');
  const checked=verify(path.join(dir,'job'),e);
  need(n.execution.execution.launches===1 && n.execution.replay.launches===0 && n.execution.replay.status==='REFUSED','DISPATCH_REPLAY');
  console.log(JSON.stringify({status:'CAPTURE_RECOMPUTED',native_signature_chain:true,process_observations:'CROSSCHECKED_NOT_ATTESTED',receipt:checked,production_ready:false}));
}catch(e){console.log(JSON.stringify({status:'REFUSED',reason:e.message}));process.exitCode=1;}
