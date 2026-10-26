"""Host witness: separate agent/broker tokens and post-state inspected outside both."""
import argparse
import copy
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from contextlib import closing

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.lab import Lab, write
from guardian import windows as win
from guardian.broker import LockedFile
from guardian.hardened import Directory
from guardian.recovery import provision
from guardian.policy import canonical,digest


class Lab02:
    def __init__(self,out,extra_actor=False):
        try:self.initialize(out,extra_actor)
        except Exception:
            for name in ('other','broker','base'):
                if hasattr(self,name):getattr(self,name).close()
            raise

    def initialize(self,out,extra_actor):
        self.out=out.absolute();self.base=Lab(self.out/'legacy-setup')
        self.root=self.base.root;self.runtime=self.base.runtime;self.resource=self.base.resource
        self.agent=self.base.container;self.broker=win.Container('Pavlo.Guardian.Broker.'+uuid.uuid4().hex)
        self.other=win.Container('Pavlo.Guardian.Other.'+uuid.uuid4().hex)
        write(self.out/'profiles.json',{'agent':self.agent.name,'broker':self.broker.name,'other':self.other.name})
        # Remove only the disposable junction itself, never traverse/delete its target.
        (self.base.inbox/'junction').rmdir()
        self.journal=self.root/'journal';self.journal.mkdir()
        provision(self.journal/'operations.sqlite')
        self.outside=self.root/'outside.txt';self.outside.write_bytes(b'outside-scope')
        shutil.copytree(ROOT/'guardian',self.runtime/'guardian',ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copyfile(ROOT/'tools/v02_worker.py',self.runtime/'v02_worker.py')
        self.policy=copy.deepcopy(self.base.policy)
        if extra_actor:self.policy['actors'].append(self.other.principal)
        self.base.policy_path.write_bytes(canonical(self.policy));self.pin=digest(canonical(self.policy))
        self.user=win.token_info()['user_sid'];self.thread=None;self.server_result=None;self.handle=None
        for path in [self.root,*self.root.rglob('*')]:
            if path.lstat().st_file_attributes & 0x400:continue
            self.acl(path)
        self.acl(self.journal,broker='FA',agent=None,other=None)
        self.acl(self.journal/'operations.sqlite',broker='FA',agent=None,other=None)
        self.acl(self.outside,broker=None,agent=None,other=None)
        self.acl(self.resource,broker='GRGW')
        win.low_label(self.root,self.journal)
        self.cfg={'root':str(self.root),'role':'server','broker_sid':self.broker.principal,'agent_sid':self.agent.principal,
          'user_sha256':digest(self.user.encode()),'policy_sha256':self.pin,'fixture_time':1000,'directories':{}}
        for name in ('.','secure','journal'):
            with Directory(self.root/name) as d:self.cfg['directories'][name]=d.identity
        with LockedFile(self.resource) as f:self.cfg['resource_identity']=f.identity
        with LockedFile(self.base.policy_path) as f:self.cfg['policy_identity']=f.identity
        write(self.out/'setup.json',{**self.cfg,'architecture':'separate zero-capability AppContainer principals, same base user'})

    def acl(self,path,broker='GRGX',agent='GRGX',other='GRGX'):
        win.safe_path(self.root,path)
        descriptor=f'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{self.user})'
        for principal,rights in ((self.broker.principal,broker),(self.agent.principal,agent),(self.other.principal,other)):
            if rights:descriptor+=f'(A;OICI;{rights};;;{principal})'
        sd=win.P();win.check(win.api(win.a,'ConvertStringSecurityDescriptorToSecurityDescriptorW',w.BOOL,w.LPCWSTR,w.DWORD,c.POINTER(win.P),win.P)(descriptor,1,c.byref(sd),None))
        try:win.check(win.api(win.a,'SetFileSecurityW',w.BOOL,w.LPCWSTR,w.DWORD,win.P)(str(path),4|0x80000000,sd))
        finally:win.local_free(sd)

    def request(self,name,**patch):
        request=self.base.request(name);request.update(patch)
        return {'schema':'guardian.ipc.v02','policy_sha256':self.pin,'request':request}

    def launch(self,container,cfg,name):
        p=self.runtime/(name+'.json');write(p,cfg);self.acl(p)
        result=container.launch([self.runtime/'python.exe','-B',*(['-O'] if sys.flags.optimize else []),self.runtime/'v02_worker.py',p],self.runtime,15)
        result['token']['user_sid_sha256']=digest(result['token'].pop('user_sid').encode())
        write(self.out/(name+'.process.json'),result);return result

    def start(self,name,**options):
        for item in ('ready.json','server.json','fatal.json','paused.json','continue'):
            p=self.journal/item
            if p.exists():p.unlink()
        suffix='Guardian-'+uuid.uuid4().hex
        cfg={**self.cfg,'pipe_local':'\\\\.\\pipe\\LOCAL\\'+suffix,**options}
        self.server_result=None
        def task():
            try:self.server_result=self.launch(self.broker,cfg,name+'-server')
            except Exception as exc:self.server_result={'error':str(exc)}
        self.thread=threading.Thread(target=task);self.thread.start()
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and self.thread.is_alive():
            if (self.journal/'ready.json').exists():break
            time.sleep(.01)
        if not (self.journal/'ready.json').exists():self.finish(name);raise RuntimeError('BROKER_START_FAILED')
        self.pid=json.loads((self.journal/'ready.json').read_bytes())['pid']
        self.handle=win.api(win.k,'OpenProcess',w.HANDLE,w.DWORD,w.BOOL,w.DWORD)(0x1000,False,self.pid);win.check(self.handle)
        actual=win.token_info(self.handle)
        if actual['appcontainer_sid']!=self.broker.principal or actual['elevated']:raise RuntimeError('BROKER_TOKEN')
        session=w.DWORD();win.check(win.api(win.k,'ProcessIdToSessionId',w.BOOL,w.DWORD,c.POINTER(w.DWORD))(self.pid,c.byref(session)))
        self.pipe='\\\\.\\pipe\\Sessions\\'+str(session.value)+'\\AppContainerNamedObjects\\'+self.broker.principal+'\\'+suffix
        return self.pid

    def client(self,name,value=None,container=None,**options):
        container=container or self.agent
        out=self.root/('client-'+uuid.uuid4().hex);out.mkdir()
        rights={'broker':None,'agent':'FA' if container is self.agent else None,'other':'FA' if container is self.other else None}
        self.acl(out,**rights);win.low_label(self.root,out)
        cfg={'root':str(self.root),'role':'client','out':str(out),'pipe':self.pipe,'server_pid':self.pid,
             'raw_hex':(value if isinstance(value,bytes) else canonical(value or self.request(name))).hex(),**options}
        result=self.launch(container,cfg,name+'-client')
        if result['exit_code']!=0:raise RuntimeError('CLIENT_FAILED')
        observed=json.loads((out/'client.json').read_bytes());write(self.out/(name+'.client.json'),observed)
        if (out/'scratch').read_bytes()!=b'positive':raise RuntimeError('CLIENT_POSITIVE_FAILED')
        return observed

    def finish(self,name):
        if self.thread:self.thread.join(18)
        if self.handle:win.close(self.handle);self.handle=None
        for file in ('server.json','fatal.json'):
            if (self.journal/file).exists():shutil.copyfile(self.journal/file,self.out/(name+'.'+file))
        write(self.out/(name+'.server-process.json'),self.server_result)
        if self.thread and self.thread.is_alive():raise RuntimeError('SERVER_HUNG')
        self.thread=None
        return self.server_result

    def roundtrip(self,name,value=None,container=None,server_options=None,**options):
        before=self.resource.read_bytes();self.start(name,**(server_options or {}))
        response=self.client(name,value,container,**options);server=self.finish(name)
        after=self.resource.read_bytes()
        row={'name':name,'response':response,'server_exit':server.get('exit_code'),
             'before_sha256':digest(before),'after_sha256':digest(after),'unchanged':before==after,
             'after_hex':after.hex()}
        write(self.out/(name+'.observation.json'),row);return row

    def probe(self,name,container,probes):
        observations=[];all_unchanged=True
        for i,probe in enumerate(probes):
            value=self.probe_one(name+'-'+str(i),container,[probe])
            observations.extend(value['rows']);all_unchanged=all_unchanged and value['unchanged']
        result={'rows':observations,'unchanged':all_unchanged,'completed':True,'observation':'host snapshot after every individual attempted operation'}
        write(self.out/(name+'.probe.json'),result);return result

    def probe_one(self,name,container,probes):
        out=self.root/('probe-'+uuid.uuid4().hex);out.mkdir()
        self.acl(out,broker='FA' if container is self.broker else None,
                 agent='FA' if container is self.agent else None,other='FA' if container is self.other else None)
        win.low_label(self.root,out)
        before={str(p):p.read_bytes() for p in (self.resource,self.base.policy_path,self.outside)}
        result=self.launch(container,{'root':str(self.root),'role':'probe','out':str(out),'probes':probes},name)
        if result['exit_code']!=0 or (out/'scratch').read_bytes()!=b'positive':raise RuntimeError('PROBE_FAILED')
        observation=json.loads((out/'probe.json').read_bytes())
        observation['unchanged']=all(p.exists() and p.read_bytes()==raw for s,raw in before.items() for p in [Path(s)])
        observation['host_snapshots']={Path(s).name:{'before_sha256':digest(raw),
          'after_sha256':digest(Path(s).read_bytes()) if Path(s).exists() else None} for s,raw in before.items()}
        write(self.out/(name+'.probe.json'),observation);return observation

    def rows(self):
        with closing(sqlite3.connect(self.journal/'operations.sqlite')) as db:
            return [{'nonce':n,'state':s,'receipt':json.loads(r) if r else None} for n,s,r in db.execute('SELECT nonce,state,receipt FROM operations ORDER BY rowid')]

    def close(self):
        if self.thread:self.finish('cleanup')
        self.other.close();self.broker.close();self.base.close()


def basic(out):
    lab=Lab02(out)
    try:
        row=lab.roundtrip('allow')
        write(out/'report.json',row);print(json.dumps(row,indent=2));return row
    finally:lab.close()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();basic(a.out.absolute())
