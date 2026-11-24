import {verifyCheckpoint} from './adapter.mjs';
export async function run(f){
 const rows=[],copy=x=>JSON.parse(JSON.stringify(x));
 async function check(name,chain=f.chain,trust=f.trust,kind='reject'){
  const r=await verifyCheckpoint(typeof chain==='string'?chain:JSON.stringify(chain),JSON.stringify(trust));
  const okay=kind==='positive'?r.checkpoint_signature==='MATCH'&&!r.error:kind==='rollback'?r.rollback_verdict==='HOLD_LOCAL_ROLLBACK_UNDER_SELECTED_PIN':!!r.error;
  rows.push({name,pass:okay&&r.trusted_latest_head==='NOT_ESTABLISHED'&&r.worker_execution==='NOT_ESTABLISHED'&&r.permission_token===null,result:r});
 }
 await check('positive',f.chain,f.trust,'positive');
 for(const field of ['state_digest','previous_checkpoint_head','session_id','policy_sha256']){const c=copy(f.chain);c[1].record[field]='tampered';await check(field,c);}
 const c=copy(f.chain);c[1].signature='A'.repeat(86)+'==';await check('signature',c);
 await check('wrong-key',f.chain,{...f.trust,public_key:'00'.repeat(32)});
 await check('wrong-state-pin',f.chain,{...f.trust,state_digests:{'2':'0'.repeat(64)}});
 await check('rollback',[f.chain[0]],f.trust,'rollback');
 await check('caller-latest-ignored',f.chain,{...f.trust,verified:true,latest_head:'CURRENT',execution:'PROVEN'},'positive');
 await check('oversize',' '.repeat(262145));
 await check('duplicate-fields','[{"record":{},"record":{}}]');
 await check('restored',f.chain,f.trust,'positive');
 return {passed:rows.filter(r=>r.pass).length,total:rows.length,rows,scope:'read-only browser module; selected state pins are not SQLite recomputation; no external anchor verification or authorization'};
}
