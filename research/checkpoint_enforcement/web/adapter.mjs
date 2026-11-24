import {parseStrict,canonicalize} from './strict-json.mjs';
const enc=new TextEncoder(),domain=enc.encode('guardian.checkpoint.v1\0');
const join=(a,b)=>new Uint8Array([...a,...b]);
const hash=async b=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',b)),x=>x.toString(16).padStart(2,'0')).join('');
const need=(b,s)=>{if(!b)throw Error(s);};
const ascii=x=>{if(typeof x==='string')need(/^[\x00-\x7f]*$/.test(x),'ASCII_PROFILE');else if(x&&typeof x==='object')for(const [k,v] of Object.entries(x)){ascii(k);ascii(v);}};
export async function verifyCheckpoint(raw,trustRaw){
 const result={checkpoint_signature:'NOT_ESTABLISHED',guardian_state_binding:'NOT_ESTABLISHED',chain_consistency:'NOT_ESTABLISHED',anchor_inclusion:'NOT_ESTABLISHED',trusted_latest_head:'NOT_ESTABLISHED',rollback_verdict:'HOLD',worker_execution:'NOT_ESTABLISHED',permission_token:null};
 try{
  const chain=parseStrict(raw),t=parseStrict(trustRaw);ascii(chain);ascii(t);
  need(t.profile==='guardian.checkpoint.browser-trust.v1'&&/^[0-9a-f]{64}$/.test(t.public_key),'INDEPENDENT_TRUST');
  need(Array.isArray(chain)&&chain.length>0&&chain.length<=64,'CHAIN_LENGTH');
  const key=await crypto.subtle.importKey('raw',Uint8Array.from(t.public_key.match(/../g),x=>parseInt(x,16)),{name:'Ed25519'},false,['verify']);
  let previous=null;
  for(let i=0;i<chain.length;i++){
   const cp=chain[i],r=cp.record;need(Object.keys(cp).sort().join('|')==='record|signature','ENVELOPE');
   need(r.schema==='guardian.checkpoint.v1'&&r.scope==='LAB_OBSERVATION_NOT_AUTHORIZATION','PROFILE');
   need(r.guardian_id===t.guardian_id&&r.session_id===t.session_id&&r.source_sha===t.source_sha&&r.policy_sha256===t.policy_sha256,'CONTEXT_BINDING');
   need(r.key_id===await hash(Uint8Array.from(t.public_key.match(/../g),x=>parseInt(x,16))),'KEY_ID');
   need(typeof cp.signature==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(cp.signature),'SIGNATURE_ENCODING');
   const sig=Uint8Array.from(atob(cp.signature),x=>x.charCodeAt(0));
   need(await crypto.subtle.verify({name:'Ed25519'},key,sig,join(domain,canonicalize(r))),'SIGNATURE_REFUTED');
   need(r.sequence===i+1&&r.previous_checkpoint_head===previous,'CHAIN_REFUTED');
   previous=await hash(join(domain,canonicalize(cp)));
  }
  result.checkpoint_signature='MATCH';result.chain_consistency='MATCH';
  const r=chain.at(-1).record;
  need(t.state_digests?.[String(r.sequence)]===r.state_digest,'STATE_PIN_REFUTED');
  result.guardian_state_binding='MATCH_UNDER_SELECTED_STATE_DIGEST';
  need(Number.isSafeInteger(t.minimum_sequence)&&t.minimum_sequence>=1&&/^[0-9a-f]{64}$/.test(t.minimum_head),'HEAD_PIN_REQUIRED');
  if(r.sequence<t.minimum_sequence)result.rollback_verdict='HOLD_LOCAL_ROLLBACK_UNDER_SELECTED_PIN';
  else {need(r.sequence===t.minimum_sequence&&previous===t.minimum_head,'HEAD_PIN_REFUTED');result.rollback_verdict='MATCH_SELECTED_HEAD_LATEST_NOT_ESTABLISHED_HOLD';}
 }catch(e){result.error=e.message;result.rollback_verdict='REFUTED_OR_UNVERIFIABLE_HOLD';}
 return result;
}
