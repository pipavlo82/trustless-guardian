"""Actual Windows processes, native SQLite faults and independent host byte checks."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.v02_lab import Lab02,write
from tools.v02_campaign import answer,allowed
from guardian import windows as win
from guardian.policy import canonical,digest


class Lab03(Lab02):
    def __init__(self,out):
        super().__init__(out)
        shutil.copyfile(ROOT/'tools/v03_worker.py',self.runtime/'v03_worker.py')
        self.acl(self.runtime/'v03_worker.py')
    def roundtrip(self,name,value=None,container=None,server_options=None,**options):
        row=super().roundtrip(name,value,container,server_options,**options)
        expected_exit=73 if (server_options or {}).get('fixture_crash') else 0
        if row['server_exit']!=expected_exit:raise RuntimeError('SERVER_CONTROL_BROKEN')
        return row
    def launch(self,container,cfg,name):
        p=self.runtime/(name+'.json');write(p,cfg);self.acl(p)
        result=container.launch([self.runtime/'python.exe','-B',*(['-O'] if sys.flags.optimize else []),self.runtime/'v03_worker.py',p],self.runtime,20)
        result['token']['user_sid_sha256']=digest(result['token'].pop('user_sid').encode())
        write(self.out/(name+'.process.json'),result);return result


def wait_file(path):
    until=time.monotonic()+6
    while not path.exists() and time.monotonic()<until:time.sleep(.01)
    if not path.exists():raise RuntimeError('LAB_BARRIER_MISSING')


def witness(kind,out):
    lab=Lab03(out)
    try:
        pos=lab.roundtrip('positive');positive=allowed(pos) and lab.resource.read_bytes()==b'approved:positive'
        options={};client={};value=lab.request('negative')
        if kind=='post_write_failure':options['fixture_commit_lock']=True
        elif kind=='prepared_failure':options['fixture_raise']='PREPARED'
        elif kind=='committed_failure':options['fixture_raise']='COMMITTED'
        elif kind=='impersonation_level':client['fixture_sqos']=2
        elif kind=='base_user':options['user_sha256']='0'*64
        elif kind=='same_bytes':
            value['request']['content']='approved:positive';options['fixture_crash']='WRITTEN'
        else:raise ValueError(kind)
        row=lab.roundtrip('negative',value,server_options=options,**client);reply=answer(row)
        journal=lab.rows();restart=None
        if kind in ('post_write_failure','prepared_failure','committed_failure','same_bytes'):
            restart=lab.roundtrip('restart',lab.request('restart',nonce='negative'))
        if kind=='post_write_failure':
            ok=not row['unchanged'] and reply.get('execution')=='RECOVERY_REQUIRED' and reply.get('status')=='UNVERIFIABLE' and reply.get('decision')=='DENY' and reply.get('failure_stage')=='COMMITTING'
            ok=ok and answer(restart).get('reason')=='RECOVERY_REQUIRED' and restart['unchanged']
        elif kind=='prepared_failure':
            ok=row['unchanged'] and reply.get('execution')=='RECOVERY_REQUIRED' and reply.get('failure_stage')=='PREPARED' and answer(restart).get('reason')=='REPLAY' and lab.rows()[-1]['state']=='ABORTED'
        elif kind=='committed_failure':
            ok=not row['unchanged'] and reply.get('execution')=='RECOVERY_REQUIRED' and reply.get('failure_stage')=='COMMITTED' and journal[-1]['state']=='COMMITTED' and answer(restart).get('reason')=='REPLAY'
        elif kind=='same_bytes':
            ok=row['server_exit']==73 and row['unchanged'] and lab.rows()[-1]['state']=='RECOVERY_REQUIRED' and answer(restart).get('reason')=='RECOVERY_REQUIRED'
        elif kind=='base_user':ok=row['unchanged'] and 'IPC_CALLER' in reply.get('reason','')
        else:
            observed=json.loads((out/'negative.server.json').read_bytes())[0]
            # This host downgrades requested impersonation to identification.
            # This observation cannot certify the added level guard as load-bearing.
            ok=allowed(row) and observed.get('identity',{}).get('impersonation_level')==1
        result={'boundary':kind,'positive_ok':positive,'negative_ok':bool(ok),'negative':row,'restart':restart,'journal_before_restart':journal,'journal_after_restart':lab.rows()}
        write(out/'witness.json',result);return result
    finally:lab.close()


def run(out):
    out=out.absolute();out.mkdir(parents=True,exist_ok=True);rows=[]
    def record(name,ok,**details):
        row={'name':name,'passed':bool(ok),**details};rows.append(row);print(json.dumps(row),flush=True)
    for kind in ('post_write_failure','prepared_failure','committed_failure','impersonation_level','same_bytes','base_user'):
        r=witness(kind,out/kind);record(kind,r['positive_ok'] and r['negative_ok'])
    lab=Lab03(out/'ipc')
    try:
        r=lab.roundtrip('allow');record('identification_allow',allowed(r) and lab.resource.read_bytes()==b'approved:allow')
        srv=json.loads((lab.out/'allow.server.json').read_bytes())[0]
        record('revert_to_self',srv['thread_after_auth']=={'present':False,'winerror':1008})
        identity=srv['identity'];record('actual_token',identity['appcontainer_sid']==lab.agent.principal and not identity['elevated'] and identity['capability_count']==0 and identity['integrity_sid']=='S-1-16-4096' and identity['user_sha256']==lab.cfg['user_sha256'])
        descriptor=json.loads((lab.journal/'ready.json').read_bytes())['dacl'];write(out/'actual-pipe-dacl.json',{'dacl':descriptor,'agent_sid':lab.agent.principal})
        for name,options in [('anonymous_sqos',{'fixture_sqos':0}),('pipe_instance_creation',{'fixture_pipe_instance':True}),('write_dac_access',{'fixture_rights':0x16019b}),('fragmented_message',{'fixture_fragment':True})]:
            r=lab.roundtrip(name,server_options={'timeout_ms':600},**options)
            observed=json.loads((lab.out/(name+'.server.json')).read_bytes())[0]['response']
            boundary=('[WinError 1347]' in observed.get('reason','') if name=='anonymous_sqos' else
                      observed.get('reason')=='IPC_SCHEMA' and observed.get('status')=='REFUTED' if name=='fragmented_message' else
                      r['response'].get('winerror')==5)
            record(name,r['unchanged'] and not allowed(r) and boundary and not r['response'].get('pipe_instance_created'),winerror=r['response'].get('winerror') if name!='fragmented_message' else None)
        raw=canonical(lab.request('two'))+canonical(lab.request('three'))
        r=lab.roundtrip('two_messages_one_frame',raw);record('two_messages_one_frame',r['unchanged'] and answer(r).get('reason')=='IPC_SCHEMA' and answer(r).get('status')=='REFUTED')
        r=lab.roundtrip('wrong_base_user',server_options={'user_sha256':'0'*64});record('wrong_base_user',r['unchanged'] and 'IPC_CALLER' in answer(r).get('reason',''))
        r=lab.roundtrip('lost_reply',fixture_drop_response=True)
        saved=lab.rows()[-1];r2=lab.roundtrip('lost_reply_replay',lab.request('lost_reply_replay',nonce='lost_reply'))
        record('lost_reply_committed',saved['state']=='COMMITTED' and saved['receipt'] is not None and lab.resource.read_bytes()==b'approved:lost_reply' and answer(r2).get('reason')=='REPLAY' and r2['unchanged'])
        # Physical ACL weakening control is a failure, even though policy may deny.
        probe=lab.probe('bypass',lab.agent,[(str(lab.resource),op) for op in ('write','delete','rename','acl')])
        record('bypass',probe['unchanged'] and all(x['result']=='OS_REJECTED' for x in probe['rows']))
    finally:lab.close()
    for failure in ('missing','corrupt','busy'):
        lab=Lab03(out/('journal-'+failure));db=None
        try:
            r=lab.roundtrip('positive');positive=allowed(r)
            path=lab.journal/'operations.sqlite'
            if failure=='missing':path.unlink()
            elif failure=='corrupt':path.write_bytes(b'not a SQLite database')
            else:db=sqlite3.connect(path);db.execute('BEGIN EXCLUSIVE')
            r=lab.roundtrip('negative')
            record('journal_'+failure,positive and r['unchanged'] and answer(r).get('status')=='UNVERIFIABLE' and answer(r).get('execution')=='NOT_EXECUTED')
        finally:
            if db:db.rollback();db.close()
            lab.close()
    # Two live broker processes, same resource/journal/nonce. Parent retains both PID handles.
    lab=Lab03(out/'two-brokers');second_thread=None;second_handle=None;client_thread=None
    try:
        request=lab.request('shared');lab.start('first',fixture_pause='PREPARED');first_pid=lab.pid;first_pipe=lab.pipe
        clients={};errors=[]
        def first_client():
            try:clients['first']=lab.client('first',request,server_pid=first_pid,pipe=first_pipe)
            except Exception as exc:errors.append(repr(exc))
        client_thread=threading.Thread(target=first_client);client_thread.start();wait_file(lab.journal/'paused.json')
        suffix='Guardian-'+uuid.uuid4().hex;cfg={**lab.cfg,'fixture_channel':'second-','pipe_local':'\\\\.\\pipe\\LOCAL\\'+suffix};result={}
        def second_server():
            try:result['process']=lab.launch(lab.broker,cfg,'second-server')
            except Exception as exc:errors.append(repr(exc))
        second_thread=threading.Thread(target=second_server);second_thread.start();wait_file(lab.journal/'second-ready.json')
        pid=json.loads((lab.journal/'second-ready.json').read_bytes())['pid']
        second_handle=win.api(win.k,'OpenProcess',w.HANDLE,w.DWORD,w.BOOL,w.DWORD)(0x1000,False,pid);win.check(second_handle)
        token=win.token_info(second_handle);session=w.DWORD();win.check(win.api(win.k,'ProcessIdToSessionId',w.BOOL,w.DWORD,c.POINTER(w.DWORD))(pid,c.byref(session)))
        pipe='\\\\.\\pipe\\Sessions\\'+str(session.value)+'\\AppContainerNamedObjects\\'+lab.broker.principal+'\\'+suffix
        clients['second']=lab.client('second',request,server_pid=pid,pipe=pipe)
        second_thread.join(20);(lab.journal/'continue').write_bytes(b'go');client_thread.join(20);lab.finish('first')
        post=lab.resource.read_bytes();journal=lab.rows();replay=lab.roundtrip('restart',lab.request('restart',nonce='shared'))
        ok=not errors and not second_thread.is_alive() and not client_thread.is_alive() and token['appcontainer_sid']==lab.broker.principal and result['process']['exit_code']==0
        ok=ok and clients['second'].get('response',{}).get('execution')=='NOT_EXECUTED' and clients['first'].get('response',{}).get('execution')=='COMMITTED' and len(journal)==1 and post==b'approved:shared' and replay['unchanged'] and answer(replay).get('reason')=='REPLAY'
        write(out/'two-brokers-observation.json',{'clients':clients,'journal':journal,'errors':errors,'after_sha256':digest(post),'second_process':result})
        record('two_brokers_one_nonce',ok)
    finally:
        (lab.journal/'continue').write_bytes(b'go')
        if client_thread:client_thread.join(20)
        if second_thread:second_thread.join(20)
        if second_handle:win.close(second_handle)
        lab.close()
    report={'schema':'guardian.conformance.v03','passed':all(r['passed'] for r in rows),'scenarios':rows,'count':len(rows),'external_reviewer':'NOT_COVERED','second_machine':'NOT_COVERED'}
    write(out/'report.json',report);write(out/'semantic.json',{'scenarios':rows});return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--witness');a=p.parse_args()
    if a.witness:witness(a.witness,a.out.absolute())
    else:raise SystemExit(not run(a.out)['passed'])
