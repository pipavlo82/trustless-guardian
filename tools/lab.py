"""Independent host witness for a disposable AppContainer + real NTFS experiment."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
import zipfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guardian import windows as win
from guardian.broker import Broker
from guardian.gateway import receive
from guardian.policy import canonical,digest


def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(json.dumps(data,sort_keys=True,indent=2).encode()+b'\n')


class Lab:
    def __init__(self,out):
        self.out=out.absolute();self.out.mkdir(parents=True,exist_ok=True)
        self.root=(ROOT/'build'/('guardian-lab-'+uuid.uuid4().hex)).absolute();self.root.mkdir()
        self.runtime=self.root/'runtime';self.runtime.mkdir()
        archive=ROOT/'build/runtime/python-3.12.10-embed-amd64.zip'
        lock=json.loads((ROOT/'runtime-lock.json').read_bytes())
        if digest(archive.read_bytes())!=lock['sha256']:raise ValueError('runtime digest')
        zipfile.ZipFile(archive).extractall(self.runtime)
        shutil.copyfile(ROOT/'tools/agent_worker.py',self.runtime/'agent_worker.py')
        self.inbox=self.root/'inbox';self.inbox.mkdir();self.secure=self.root/'secure';self.secure.mkdir()
        self.resource=self.secure/'resource.txt';self.resource.write_bytes(b'initial\n')
        self.container=win.Container('Pavlo.Guardian.'+uuid.uuid4().hex)
        self.principal=self.container.principal
        self.policy={'schema':'guardian.policy.v0','version':'guardian.local-file.v0','actors':[self.principal],
          'action':'replace_utf8','resource':'sample','scope':'whole-file-laboratory','max_bytes':128,'max_ttl':60,'content_prefix':'approved:'}
        self.policy_path=self.secure/'policy.json';self.policy_path.write_bytes(canonical(self.policy))
        self.pin=digest(canonical(self.policy));self.broker=Broker(self.root,self.pin)
        self.acls={}
        for path in [self.root,*self.root.rglob('*')]:
            self.acls[str(path.relative_to(self.root))]=win.acl(self.root,path,self.principal)
        self.acls['inbox']=win.acl(self.root,self.inbox,self.principal,True)
        self.labels={'inbox':win.low_label(self.root,self.inbox),'resource':win.low_label(self.root,self.resource)}
        write(self.out/'label-setup.json',self.labels)
        junction=subprocess.run(['cmd','/d','/c','mklink','/J',str(self.inbox/'junction'),str(self.secure)],capture_output=True)
        write(self.out/'junction-setup.json',{'argv':['cmd','/d','/c','mklink','/J',str(self.inbox/'junction'),str(self.secure)],'exit_code':junction.returncode})
        (self.out/'junction.stdout').write_bytes(junction.stdout);(self.out/'junction.stderr').write_bytes(junction.stderr)
        if junction.returncode:raise RuntimeError('junction fixture unavailable')
        token=win.token_info();token['user_sid_sha256']=digest(token.pop('user_sid').encode())
        write(self.out/'setup.json',{'root':str(self.root),'broker_token':token,'agent_sid':self.principal,
              'policy':self.policy,'policy_sha256':self.pin,'resource_identity':self.broker.identity,
              'acl_sddl':{k:v.replace(win.token_info()['user_sid'],'<trusted-broker-user-SID>') for k,v in self.acls.items()},
              'runtime':lock,'python':sys.version,'platform':sys.platform})

    def request(self,nonce):
        return {'schema':'guardian.action.v0','actor':self.principal,'action':'replace_utf8','resource':'sample',
          'scope':'whole-file-laboratory','policy_version':self.policy['version'],'expires_at':1030,'nonce':nonce,
          'content':'approved:'+nonce,'evidence':{'before_sha256':digest(self.resource.read_bytes())}}

    def agent(self,name,mode,request=None):
        out=self.inbox/name;out.mkdir();win.acl(self.root,out,self.principal,True);win.low_label(self.root,out)
        # For bypass, a junction is created inside this specific agent-writable inbox.
        if mode!='request':
            p=subprocess.run(['cmd','/d','/c','mklink','/J',str(out/'junction'),str(self.secure)],capture_output=True)
            if p.returncode:raise RuntimeError('agent junction fixture unavailable')
        config={'mode':mode,'out':str(out),'resource':str(self.resource),'policy':str(self.policy_path),'request':request}
        cfg=self.runtime/(name+'.json');write(cfg,config);win.acl(self.root,cfg,self.principal)
        result=self.container.launch([self.runtime/'python.exe','-I',self.runtime/'agent_worker.py',cfg],self.runtime)
        result['token']['user_sid_sha256']=digest(result['token'].pop('user_sid').encode())
        write(self.out/(name+'.process.json'),result)
        if result['exit_code']!=0 or not (out/'worker.json').exists():raise RuntimeError('agent did not execute: '+name)
        worker=json.loads((out/'worker.json').read_bytes());write(self.out/(name+'.worker.json'),worker)
        return out,worker,result

    def check_request(self,name,patch=None,preexecute=None,presented=None):
        before=self.resource.read_bytes();r=self.request(name)
        if patch:r.update(patch)
        inbox,_,process=self.agent(name,'request',r)
        raw=(inbox/'request.json').read_bytes();request,proposed=receive(raw,self.policy,process['token']['appcontainer_sid'],1000,digest(before),set())
        if preexecute:preexecute()
        record=self.broker.execute(request,process['token']['appcontainer_sid'],1000,presented=presented)
        record_path=self.out/(name+'.evidence.json');write(record_path,record)
        cmd=[sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),str(ROOT/'guardian/verifier.py'),str(record_path),'--policy-sha256',self.pin,'--head',record['sha256']]
        p=subprocess.run(cmd,capture_output=True);(self.out/(name+'.verify.stdout')).write_bytes(p.stdout);(self.out/(name+'.verify.stderr')).write_bytes(p.stderr)
        write(self.out/(name+'.verify.command.json'),{'argv':cmd,'exit_code':p.returncode})
        b=record['body'];actual=self.resource.read_bytes()
        return {'name':name,'decision':b['decision'],'broker_result':b['broker_result'],
                'before_sha256':digest(before),'after_sha256':digest(actual),'independent_verifier_exit':p.returncode,
                'host_matches_record':digest(actual)==b['after_sha256'],'gateway_proposed':proposed['decision']}

    def bypass(self,name='bypass',weaken=False):
        before=self.resource.read_bytes()
        if weaken:win.acl(self.root,self.resource,self.principal,True)
        out,worker,process=self.agent(name,'single_write' if weaken else 'bypass')
        actual=self.resource.read_bytes() if self.resource.exists() else None
        if (out/'hardlink.txt').exists():(out/'hardlink.txt').unlink()
        if weaken:win.acl(self.root,self.resource,self.principal)
        return {'name':name,'rows':worker['rows'],'agent_completed':worker['completed'],
          'appcontainer':process['token']['appcontainer'],'low_integrity':process['token']['integrity_sid']=='S-1-16-4096',
          'before_sha256':digest(before),'after_sha256':digest(actual) if actual is not None else None,
          'unchanged':actual==before}

    def close(self):self.container.close()


def run(out):
    started=time.perf_counter();lab=Lab(out);rows=[]
    try:
        rows.append(lab.check_request('allow'))
        patches={'deny_action':{'action':'delete'},'wrong_actor':{'actor':'untrusted'},'wrong_resource':{'resource':'other'},
          'expired':{'expires_at':999},'future_expiry':{'expires_at':2000},'wrong_version':{'policy_version':'old'},
          'missing_evidence':{'evidence':{}},'wrong_precondition':{'evidence':{'before_sha256':'0'*64}},
          'wrong_scope':{'scope':'arbitrary-execution'},'unconsumed_field':{'authorized':True},
          'wrong_path':{'resource':str(lab.resource)},'bad_content':{'content':'unauthorized'}}
        for name,patch in patches.items():rows.append(lab.check_request(name,patch))
        rows.append(lab.check_request('forged_gateway_allow',{'action':'delete'},presented={'authorized':True,'decision':'ALLOW'}))
        # Same durable nonce, independently observed pre-state, same broker database.
        rows.append(lab.check_request('replay',{'nonce':'allow'}))
        rows.append(lab.check_request('policy_change',preexecute=lambda:lab.policy_path.write_bytes(canonical({**lab.policy,'version':'changed'}))))
        lab.policy_path.write_bytes(canonical(lab.policy))
        saved=lab.secure/'original.txt'
        def replace_identity():
            lab.resource.rename(saved);lab.resource.write_bytes(saved.read_bytes());win.acl(lab.root,lab.resource,lab.principal)
        rows.append(lab.check_request('resource_replacement',preexecute=replace_identity))
        lab.resource.unlink();saved.rename(lab.resource)
        bypass=lab.bypass();write(out/'bypass.json',bypass)
        unavailable=[]
        for name in ('gateway_unavailable','broker_unavailable'):
            # No gateway/broker dispatch. Agent still executes the direct attacks.
            r=lab.bypass(name);write(out/(name+'.json'),r);unavailable.append(r)
        original=json.loads((out/'allow.evidence.json').read_bytes());tampered=copy.deepcopy(original);tampered['body']['after_sha256']='0'*64
        path=out/'tampered.evidence.json';write(path,tampered)
        cmd=[sys.executable,'-B',str(ROOT/'guardian/verifier.py'),str(path),'--policy-sha256',lab.pin,'--head',original['sha256']]
        p=subprocess.run(cmd,capture_output=True);(out/'tampered.stdout').write_bytes(p.stdout);(out/'tampered.stderr').write_bytes(p.stderr)
        write(out/'tampered.command.json',{'argv':cmd,'exit_code':p.returncode})
        protected_checks=[r for r in bypass['rows'] if r['name'] not in ('scratch_positive','hardlink_create')]
        os_pass=(bypass['unchanged'] and bypass['appcontainer'] and bypass['low_integrity'] and
          bypass['rows'][0]['result']=='SUCCEEDED' and all(r['result']=='OS_REJECTED' for r in protected_checks))
        policy_pass=all(r['independent_verifier_exit']==0 and r['host_matches_record'] and
          r['decision']['decision']==('ALLOW' if r['name']=='allow' else 'DENY') and
          (r['name']=='allow' or r['before_sha256']==r['after_sha256']) for r in rows)
        summary={'schema':'guardian.conformance.v0','passed':policy_pass and os_pass and all(r['unchanged'] for r in unavailable) and p.returncode==1,
          'policy_cases':rows,'bypass':bypass,'unavailable_cases':unavailable,'tamper_exit':p.returncode,
          'seconds':time.perf_counter()-started,'os_enforcement':'LABORATORY_VERIFIED' if os_pass else 'FAILED',
          'external_execution':'UNVERIFIABLE','production_ready':False}
        write(out/'summary.json',summary)
        semantic={'cases':[{k:r[k] for k in ('name','broker_result','before_sha256','after_sha256','independent_verifier_exit','host_matches_record')}|{'decision':r['decision']['decision'],'reason':r['decision']['reason']} for r in rows],
                  'bypass':bypass['rows'],'unchanged':bypass['unchanged'],'tamper_exit':p.returncode}
        write(out/'semantic.json',semantic);print(json.dumps({'passed':summary['passed'],'policy_cases':len(rows),'bypass':os_pass,'seconds':summary['seconds']}))
        return summary
    finally:lab.close()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=ROOT/'build/lab');args=p.parse_args()
    raise SystemExit(not run(args.out.absolute())['passed'])
