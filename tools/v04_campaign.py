"""Real-process fault campaign. Expectations are fixed before implementation runs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.v03_campaign import Lab03
from tools.lab import write

# Explicit fault model, not implementation-derived expectations.
CASES={
 'runtime_after_write':(b'approved:negative','RECOVERY_REQUIRED','RECOVERY_REQUIRED'),
 'runtime_after_commit':(b'approved:negative','COMMITTED','REPLAY'),
 'prepare_return_failure':(b'approved:positive','ABORTED','REPLAY'),
 'journal_write_failure':(b'approved:positive',None,'ALLOW_NEW'),
 'resource_write_failure':(b'approved:positive','ABORTED','REPLAY'),
 'partial_write_failure':(b'approved:negative'[:len(b'approved:negative')//2],'RECOVERY_REQUIRED','RECOVERY_REQUIRED'),
 'flush_failure':(b'approved:negative','RECOVERY_REQUIRED','RECOVERY_REQUIRED'),
 'readback_failure':(b'approved:negative','RECOVERY_REQUIRED','RECOVERY_REQUIRED'),
 'readback_mismatch':(b'actual-wrong-bytes','RECOVERY_REQUIRED','RECOVERY_REQUIRED'),
 'journal_close_failure':(b'approved:negative','COMMITTED','REPLAY'),
 'dispatch_return_failure':(b'approved:negative','COMMITTED','REPLAY'),
 'sqlite_commit_failure':(b'approved:negative','RECOVERY_REQUIRED','RECOVERY_REQUIRED'),
 'crash_written':(b'approved:negative','RECOVERY_REQUIRED','RECOVERY_REQUIRED'),
 'same_bytes':(b'approved:positive','RECOVERY_REQUIRED','RECOVERY_REQUIRED'),
}

class Lab04(Lab03):
    def __init__(self,out):
        super().__init__(out)
        for name in ('v04_worker.py','v04_native.py','v04_token_probe.py'):
            shutil.copyfile(ROOT/'tools'/name,self.runtime/name);self.acl(self.runtime/name)
    def snapshot(self,name,pid=None):
        out=self.out/(name+'.native.json')
        argv=[sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),str(ROOT/'tools/v04_oracle.py'),'--snapshot',str(self.resource),'--out',str(out)]+(['--pid',str(pid)] if pid else [])
        p=subprocess.run(argv,capture_output=True);(self.out/(name+'.native.stderr')).write_bytes(p.stderr)
        write(self.out/(name+'.native.command.json'),{'argv':argv,'exit_code':p.returncode})
        if p.returncode:raise RuntimeError('INDEPENDENT_OBSERVER_FAILED')
        return json.loads(out.read_bytes())
    def start(self,name,**options):
        pid=super().start(name,**options);self.server_observation=self.snapshot(name+'-server',pid);return pid
    def roundtrip(self,name,*args,**kwargs):
        before=self.snapshot(name+'-before');row=super().roundtrip(name,*args,**kwargs)
        row['independent_host']={'before':before,'after':self.snapshot(name+'-after'),'server':self.server_observation}
        write(self.out/(name+'.observation.json'),row);return row
    def launch(self,container,cfg,name):
        path=self.runtime/(name+'.json');write(path,cfg);self.acl(path)
        result=container.launch([self.runtime/'python.exe','-B',*(['-O'] if sys.flags.optimize else []),self.runtime/'v04_worker.py',path],self.runtime,20)
        result['token']['user_sid_sha256']=hashlib.sha256(result['token'].pop('user_sid').encode()).hexdigest()
        write(self.out/(name+'.process.json'),result);return result

def oracle(out,value):
    write(out/'oracle-input.json',value)
    argv=[sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),str(ROOT/'tools/v04_oracle.py'),str(out/'oracle-input.json')]
    p=subprocess.run(argv,capture_output=True);(out/'oracle.stdout').write_bytes(p.stdout);(out/'oracle.stderr').write_bytes(p.stderr)
    write(out/'oracle-command.json',{'argv':argv,'exit_code':p.returncode})
    return json.loads(p.stdout) if p.returncode in (0,1,2) and p.stdout else {'passed':False,'control_broken':'missing oracle result'}

def witness(case,out,legacy=False):
    lab=Lab04(out)
    try:
        if case=='token':
            from guardian import windows as win
            folder=lab.root/'token-output';folder.mkdir();lab.acl(folder,agent='FA',broker=None,other=None);win.low_label(lab.root,folder)
            before=lab.snapshot('token-before');dest=folder/'probe.json'
            p=lab.agent.launch([lab.runtime/'python.exe','-B',*(['-O'] if sys.flags.optimize else []),lab.runtime/'v04_token_probe.py',dest],lab.runtime,20)
            p['token']['user_sid_sha256']=hashlib.sha256(p['token'].pop('user_sid').encode()).hexdigest();write(out/'token-process.json',p)
            if p['exit_code']!=0 or not dest.exists():raise RuntimeError('TOKEN_CONTROL_BROKEN')
            probe=json.loads(dest.read_bytes());write(out/'token-probe.json',probe)
            value={'kind':'token','probe':probe,'before_hex':before['hex'],'after_hex':lab.snapshot('token-after')['hex']}
        else:
            pos=lab.roundtrip('positive',server_options={'v04_legacy_dispatch':legacy});before=lab.resource.read_bytes()
            after,state,reason=CASES[case];options={'v04_fault':case,'v04_legacy_dispatch':legacy};request=lab.request('negative')
            if case=='sqlite_commit_failure':options['fixture_commit_lock']=True
            if case in ('same_bytes','crash_written'):
                options['fixture_crash']='WRITTEN'
                if case=='same_bytes':request['request']['content']='approved:positive'
            row=lab.roundtrip('negative',request,server_options=options)
            fault=json.loads((lab.journal/'fault.json').read_bytes()) if (lab.journal/'fault.json').exists() else {}
            # Capture before restart can overwrite process fault output.
            write(out/'fault.json',fault)
            if reason=='ALLOW_NEW':
                # No durable negative prepare exists. Replay a malformed request so
                # it cannot change bytes, and inspect the single positive journal row.
                bad=lab.request('restart',nonce='negative');bad['request']['actor']='untrusted'
                restart=lab.roundtrip('restart',bad,server_options={'v04_legacy_dispatch':legacy});reason='ACTOR'
            else:restart=lab.roundtrip('restart',lab.request('restart',nonce='negative'),server_options={'v04_legacy_dispatch':legacy})
            value={'kind':'outcome','case':case,'positive':pos,'before_hex':before.hex(),'observation':row,'fault':fault,'restart':restart,'journal':lab.rows(),'broker_sid':lab.broker.principal,
              'expected':{'after_hex':after.hex(),'state':state,'restart_reason':reason,'exit':73 if case in ('same_bytes','crash_written') else 0}}
        result=oracle(out,value);write(out/'witness.json',result);return result
    finally:lab.close()

def run(out,selected=None,legacy=False):
    out=out.absolute();out.mkdir(parents=True,exist_ok=False);rows=[]
    for name in ([selected] if selected else [*CASES,'token']):
        target=out/name
        try:r=witness(name,target,legacy)
        except Exception as e:
            target.mkdir(parents=True,exist_ok=True);r={'passed':False,'control_broken':repr(e)};write(target/'witness.json',r)
        rows.append({'case':name,**r});print(json.dumps(rows[-1]),flush=True)
    report={'schema':'guardian.conformance.v04','passed':all(r['passed'] for r in rows),'scenarios':rows,'legacy_dispatch':legacy,'second_machine':'NOT_COVERED'}
    write(out/'report.json',report);write(out/'semantic.json',{'scenarios':rows});return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--witness');p.add_argument('--legacy-dispatch',action='store_true');a=p.parse_args()
    raise SystemExit(not run(a.out,a.witness,a.legacy_dispatch)['passed'])
