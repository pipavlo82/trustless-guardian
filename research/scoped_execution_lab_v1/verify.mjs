// Separate Node/OpenSSL implementation. No imports of the Python decision logic.
// Trust/expectations must be selected out-of-band; not authority supplied by a receipt.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
export function canon(x) {
  if (x===null || typeof x==='boolean') return JSON.stringify(x);
  if (typeof x==='number' && Number.isSafeInteger(x)) return String(x);
  if (typeof x==='string' && /^[\x00-\x7f]*$/.test(x)) return JSON.stringify(x);
  if (Array.isArray(x)) return '['+x.map(canon).join(',')+']';
  if (x && Object.getPrototypeOf(x)===Object.prototype) return '{'+Object.keys(x).sort().map(k=>canon(k)+':'+canon(x[k])).join(',')+'}';
  throw Error('CANONICAL_DOMAIN');
}
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function need(ok,why){if(!ok)throw Error(why);}
function key(raw){need(/^[a-f0-9]{64}$/.test(raw),'KEY');return crypto.createPublicKey({key:Buffer.from('302a300506032b6570032100'+raw,'hex'),format:'der',type:'spki'});}
function signed(x,pub){
  need(Object.keys(x).sort().join(',')==='payload,public_key_fingerprint,signature','ENVELOPE');
  need(x.public_key_fingerprint===sha(Buffer.from(pub,'hex')).slice(0,24),'SIGNER');
  const sig=Buffer.from(x.signature,'base64');need(sig.length===64 && sig.toString('base64')===x.signature,'SIGNATURE_ENCODING');
  need(crypto.verify(null,Buffer.from(canon(x.payload)),key(pub),sig),'SIGNATURE');return x.payload;
}
function load(file){const raw=fs.readFileSync(file);const obj=JSON.parse(raw);need(raw.equals(Buffer.from(canon(obj)+'\n')),'NONCANONICAL_FILE');return obj;}
export function verify(dir,expected){
  const req=load(path.join(dir,'request.json')),g=load(path.join(dir,'grant.json')),r=load(path.join(dir,'receipt.json')),o=load(path.join(dir,'outcome.json'));
  need(canon(req)===canon(expected.request),'EXPECTED_REQUEST');
  const gp=signed(g,expected.grant_public),rp=signed(r,expected.receipt_public);
  const binding={...req,body_sha256:sha(canon(req.body))};delete binding.schema;delete binding.body;
  need(gp.schema==='guardian.execution-grant.v2' && gp.authorization==='ALLOW' && gp.anomaly_authorization_input===false,'GRANT_TYPE');
  need(canon(gp.binding)===canon(binding) && gp.binding_sha256===sha(canon(binding)),'GRANT_REQUEST');
  need(gp.subject===expected.sid && gp.role==='LAB_SYNTHETIC','SUBJECT');
  need(gp.admission_scope===expected.scope && gp.trust_version===expected.trust_version && gp.image_identity===expected.image && gp.worker_sha256===expected.worker_sha256,'SCOPE');
  need(gp.grant_key_fingerprint===g.public_key_fingerprint,'GRANT_KEY');
  need(Number.isSafeInteger(gp.not_before)&&Number.isSafeInteger(gp.expires_at)&&gp.expires_at-gp.not_before===60 && Number.isSafeInteger(rp.recorded_at) && gp.not_before<=rp.recorded_at && rp.recorded_at<gp.expires_at,'TIME');
  const policy=expected.policy;
  need(policy.schema==='guardian.synthetic-policy.v1' && policy.enabled===true && policy.revoked===false && policy.epoch===1 && policy.sid===expected.sid && policy.not_before<=rp.recorded_at && rp.recorded_at<policy.expires_at,'POLICY_AT_CAPTURE');
  need(req.body.policy_sha256===sha(canon(policy)),'POLICY_BINDING');
  need(rp.schema==='guardian.execution-receipt.v1' && rp.classification==='EXECUTED' && rp.lifecycle==='COMMITTED' && rp.container_started===true && rp.exit_code===0 && rp.timed_out===false && rp.launch_error===null,'NO_SUCCESS_OBSERVATION');
  const matches={request_id:req.request_id,request_sha256:sha(canon(binding)),grant_id:gp.grant_id,grant_sha256:sha(canon(g)),grant_signature_sha256:sha(Buffer.from(g.signature,'base64')),grant_key_fingerprint:g.public_key_fingerprint,worker_sha256:expected.worker_sha256,image_identity:expected.image,admission_scope:expected.scope,trust_version:expected.trust_version};
  need(Object.entries(matches).every(([k,v])=>rp[k]===v),'RECEIPT_BINDING');
  need(canon(rp.principal)===canon({subject:gp.subject,role:gp.role,wallet:gp.wallet}),'PRINCIPAL');
  const so=fs.readFileSync(path.join(dir,'stdout.bin')),se=fs.readFileSync(path.join(dir,'stderr.bin'));
  need(sha(so)===rp.stdout_sha256&&sha(se)===rp.stderr_sha256 && sha(canon(o))===rp.outcome_sha256,'OUTPUT_BINDING');
  const observed={container_started:rp.container_started,exit_code:rp.exit_code,timed_out:rp.timed_out,launch_error:rp.launch_error,outcome_sha256:rp.outcome_sha256,stdout_sha256:rp.stdout_sha256,stderr_sha256:rp.stderr_sha256};
  need(Object.entries(observed).filter(([k])=>k!=='outcome_sha256').every(([k,v])=>o[k]===v),'OUTCOME_CONTRADICTION');
  need(sha(canon(observed))===rp.evidence_sha256 && o.cleanup===true,'EVIDENCE_BINDING');
  const want=canon({action:'synthetic_request_hash',request_file_sha256:sha(canon(req)+'\n'),uid:65534})+'\n';
  need(so.equals(Buffer.from(want)) && se.length===0,'SYNTHETIC_RECOMPUTE');
  return {status:'VERIFIED_UNDER_DECLARED_LAB_ASSUMPTIONS',request_sha256:sha(canon(binding)),action:'synthetic_request_hash',current_authorization:'NOT_ESTABLISHED',production_ready:false};
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{const result=verify(process.argv[2],load(process.argv[3]));console.log(JSON.stringify(result));}
  catch(e){console.log(JSON.stringify({status:'REFUSED',reason:e.message}));process.exitCode=1;}
}
