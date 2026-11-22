"""Physical controls with fixed expected refusals; no checker decision imports."""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys,tempfile
ROOT=Path(__file__).resolve().parents[1]
P='research/stack_ci_transition_v1/INVENTORY.json';W='.github/workflows/guardian.yml';G='tools/stack_integrity_v1.py'

def sha(raw):return hashlib.sha256(raw).hexdigest()
def run(out,pin):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    scratch=out/'copy'
    # Self-contained separate checkout of committed candidate; no in-place test mutations.
    p=subprocess.run(['git','clone','--no-hardlinks','--no-checkout',str(ROOT),str(scratch)],capture_output=True)
    if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace'))
    for args in [('config','core.autocrlf','false'),('config','core.eol','lf'),('checkout','--detach',subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip())]:
        subprocess.run(['git',*args],cwd=scratch,check=True,capture_output=True)
    original={n:(scratch/n).read_bytes() for n in [P,W,G,'tools/integrity.py','guardian/protocol.py']}
    if sha(original[P])!=pin:raise RuntimeError('CHECKOUT_PIN_MISMATCH')
    rows=[];seq=0
    def reset():
        for n,raw in original.items():(scratch/n).write_bytes(raw)
        extra=scratch/'unapproved.txt'
        if extra.exists():extra.unlink()
    def seal(policy):
        raw=(json.dumps(policy,sort_keys=True,indent=2)+'\n').encode();newpin=sha(raw)
        (scratch/P).write_bytes(raw)
        (scratch/W).write_bytes(original[W].replace(pin.encode(),newpin.encode()))
        return newpin
    def invocation(label,selected,flags):
        nonlocal seq
        seq+=1;args=[sys.executable,'-B',*flags,str(scratch/G),'--root',str(scratch),'--pin',selected]
        p=subprocess.run(args,cwd=scratch,capture_output=True)
        stem=out/f'{seq:03d}-{label}';stem.with_suffix('.stdout').write_bytes(p.stdout);stem.with_suffix('.stderr').write_bytes(p.stderr)
        try:r=json.loads(p.stdout)
        except (ValueError,TypeError):r={}
        return {'command':args,'exit_code':p.returncode,'status':r.get('status'),'reason':r.get('reason'),'evidence':stem.name}
    def perturb(kind,selected):
        policy=json.loads((scratch/P).read_bytes())
        if kind=='extra':(scratch/'unapproved.txt').write_bytes(b'unauthorized\n')
        elif kind=='content':(scratch/'tools/integrity.py').write_bytes(original['tools/integrity.py']+b'\n# unauthorized\n')
        elif kind=='missing':(scratch/'guardian/protocol.py').unlink()
        elif kind=='policy_pin':
            wrong='0'*64;(scratch/W).write_bytes((scratch/W).read_bytes().replace(selected.encode(),wrong.encode()));return wrong
        elif kind=='historical_metadata':
            policy['frozen_files']['guardian/protocol.py']='0'*64;return seal(policy)
        elif kind=='count':policy['research_addition_count']+=1;return seal(policy)
        elif kind=='transition':
            data=original['tools/integrity.py']+b'\n# unauthorized\n';(scratch/'tools/integrity.py').write_bytes(data)
            policy['changed']['tools/integrity.py']=sha(data);return seal(policy)
        elif kind=='overwrite':policy['added']['guardian/protocol.py']=sha(original['guardian/protocol.py']);return seal(policy)
        return selected
    mutations=[
      ('path_set',"if names != set(expected) | {POLICY}:","if False:",'extra'),
      ('content',"if digest(content) != value:","if False:",'content'),
      ('policy_pin',"if digest(raw) != pin:","if False:",'policy_pin'),
      ('historical_identity',"if historical != policy['frozen_files'] or upstream != policy['source_files']:","if False:",'historical_metadata'),
      ('declared_extension',"if additions != policy['research_additions'] or len(additions) != policy['research_addition_count']:","if False:",'count'),
      ('transition_scope',"if set(policy['changed']) != {'README.md', WORKFLOW}:","if False:",'transition'),
      ('no_overwrite',"if any(name in upstream for name in policy['added']):","if False:",'overwrite')]
    for mode,flags in [('normal',[]),('repeat',[]),('optimized',['-O'])]:
        reset();healthy=invocation(mode+'-healthy',pin,flags)
        for kind in ['extra','content','missing','policy_pin','historical_metadata','count','transition','overwrite']:
            reset();selected=perturb(kind,pin);negative=invocation(mode+'-'+kind,selected,flags)
            reset();restored=invocation(mode+'-restored',pin,flags)
            rows.append({'mode':mode,'kind':'NEGATIVE_CONTROL','id':kind,'positive':healthy,'negative':negative,'restored':restored,
                         'result':'PASS' if healthy['status']=='VERIFIED_TRANSITION' and negative['status']=='REFUSED' and negative['exit_code']==1 and restored['status']=='VERIFIED_TRANSITION' else 'FAIL'})
        for name,before,after,witness in mutations:
            reset();text=original[G].decode();count=text.count(before)
            if count!=1:rows.append({'mode':mode,'kind':'MUTATION','id':name,'result':'NOT_APPLIED','matches':count});continue
            # Isolated mutation policy explicitly re-pins ONLY the new guard implementation.
            # Historical pins are never modified to hide the mutant. Negative policy examples
            # are independent witnesses to governance constraints, not approved transitions.
            modified=text.replace(before,after).encode();(scratch/G).write_bytes(modified)
            policy=json.loads(original[P]);policy['added'][G]=sha(modified);selected=seal(policy)
            positive=invocation(mode+'-'+name+'-mutant-positive',selected,flags)
            selected=perturb(witness,selected);negative=invocation(mode+'-'+name+'-mutant-negative',selected,flags)
            reset();restored=invocation(mode+'-'+name+'-restored',pin,flags)
            if positive['status']!='VERIFIED_TRANSITION' or restored['status']!='VERIFIED_TRANSITION':grade='CONTROL_BROKEN'
            elif negative['exit_code']==0 and negative['status']=='VERIFIED_TRANSITION':grade='KILLED'
            elif negative['exit_code']==1 and negative['status']=='REFUSED':grade='SURVIVED'
            else:grade='CRASHED'
            rows.append({'mode':mode,'kind':'MUTATION','id':name,'matches':count,'before':before,'after':after,'witness':witness,'positive':positive,'negative':negative,'restored':restored,'result':grade})
    reset()
    status=subprocess.check_output(['git','status','--porcelain'],cwd=scratch).decode()
    result={'schema':'guardian.stack-controls.v1','rows':rows,'source_restored':status=='','unique_guards':len(mutations),
            'passed':status=='' and all(r['result'] in ('PASS','KILLED') for r in rows),'native_windows':'NOT_TESTED_BY_THIS_SUITE'}
    (out/'report.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'passed':result['passed'],'rows':len(rows),'unique_guards':len(mutations),'source_restored':status==''}),flush=True)
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--pin',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    raise SystemExit(0 if run(a.out,a.pin)['passed'] else 1)
