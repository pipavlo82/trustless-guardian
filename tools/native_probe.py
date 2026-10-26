"""Read-only native invocation audit. Results are evidence, never action authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.validate import write

PINS={'receiptos-verify':'f39ac3b289be6baef1140c53976d525d8eb45c8c',
      'verifiable-execution-claim-authorization':'e2aca1a029203f1d5c73db2f8872b4240e793bfb',
      'recompute-kit':'b4537d73bda4e4df73c4b105ee516a43c351ba02'}


def run(source_root,out):
    out.mkdir(parents=True,exist_ok=False);rows=[]
    for name,pin in PINS.items():
        path=source_root/name
        head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=path,text=True).strip()
        clean=subprocess.check_output(['git','status','--porcelain=v1'],cwd=path,text=True)
        if head!=pin or clean:raise ValueError('PIN_OR_WORKTREE_CHANGED: '+name)
        # An explicit input fixture runs the genuine entry point if prerequisites exist.
        if name=='receiptos-verify':
            code="""import {pathToFileURL} from 'node:url';
const base=process.cwd()+'/';
const {baselineV2}=await import(pathToFileURL(base+'tools/fixtures-v2.mjs'));
const {verifyV2}=await import(pathToFileURL(base+'src/core/verify-v2.mjs'));
const pair=await baselineV2();const wrong=structuredClone(pair.request);wrong.scope={arbitrary:'execution'};
console.log(JSON.stringify({input:pair,positive:await verifyV2(pair.request,pair.bundle),wrong_scope:await verifyV2(wrong,pair.bundle)}));"""
            argv=['node','--input-type=module','-e',code]
        elif name=='verifiable-execution-claim-authorization':
            code="from src.integration.cases import base;from src.integration.engine import evaluate,admit;import json;c=base();r=evaluate(c);forged=dict(r,authorized=True);print(json.dumps({'input':c,'evaluated':r,'admitted':admit(r,c),'forged_admitted':admit(forged,c)}))"
            argv=[sys.executable,'-B','-c',code]
        else:
            # Interface/source audit; no fabricated native action subject in this probe.
            rows.append({'repository':name,'commit':pin,'native_integration':'NOT_COVERED','reason':'No evidence-to-Guardian-action contract implemented','execution_authority':False});continue
        try:
            p=subprocess.run(argv,cwd=path,capture_output=True,timeout=120,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
            stdout,stderr,code=p.stdout,p.stderr,p.returncode
        except subprocess.TimeoutExpired as exc:stdout,stderr,code=exc.stdout or b'',exc.stderr or b'',None
        (out/(name+'.stdout')).write_bytes(stdout);(out/(name+'.stderr')).write_bytes(stderr)
        row={'repository':name,'commit':pin,'argv':argv,'exit_code':code,'native_output_sha256':hashlib.sha256(stdout).hexdigest(),
             'native_invocation':'EXECUTED' if code==0 else 'NOT_COVERED','guardian_action_binding':'NOT_COVERED','execution_authority':False}
        if code==0:
            try:row['native_output']=json.loads(stdout)
            except ValueError:row['native_invocation']='NOT_COVERED'
        if subprocess.check_output(['git','status','--porcelain=v1'],cwd=path,text=True):raise ValueError('UPSTREAM_CHANGED')
        rows.append(row)
    write(out/'report.json',{'schema':'guardian.native-probe.v02','sources':rows,'full_integration':'NOT_COVERED','guardian_authorization':'UNVERIFIABLE'})
    print(json.dumps([{k:r.get(k) for k in ('repository','commit','native_invocation','guardian_action_binding','exit_code')} for r in rows]))


if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--source-root',type=Path,required=True);a.add_argument('--out',type=Path,required=True);v=a.parse_args();run(v.source_root,v.out)
