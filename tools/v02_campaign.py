"""Finite adversarial OS witnesses, independent expected results, no unavailable PASS."""
import argparse
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.v02_lab import Lab02,write
from guardian.policy import canonical,digest


def answer(row):return row['response'].get('response',{})
def allowed(row):return answer(row).get('execution')=='COMMITTED'


def witness(kind,out):
    lab=Lab02(out,extra_actor=kind=='caller_identity')
    try:
        positive=lab.roundtrip('positive');positive_ok=allowed(positive) and lab.resource.read_bytes()==b'approved:positive'
        value=lab.request('negative');options={};client_options={};container=None
        if kind=='envelope_pin':value['policy_sha256']='0'*64
        elif kind=='caller_identity':
            value['request']['actor']=lab.other.principal;container=lab.other;options['fixture_pipe_sid']=lab.other.principal
        elif kind=='server_identity':client_options['server_pid']=0
        elif kind=='policy_pin':lab.base.policy_path.write_bytes(canonical({**lab.policy,'max_bytes':129}))
        elif kind=='resource_identity':
            lab.resource.rename(lab.root/'original.txt');lab.resource.write_bytes(b'approved:positive');lab.acl(lab.resource,broker='GRGW')
            from guardian import windows as win
            win.low_label(lab.root,lab.resource)
        elif kind=='directory_identity':
            secure=lab.root/'secure';old=lab.root/'original-parent';secure.rename(old);secure.mkdir();lab.acl(secure)
            for name in ('resource.txt','policy.json'):(old/name).rename(secure/name)
        elif kind=='enforcement':value['request']['content']='not-authorized'
        elif kind=='recovery_gate':
            crash=lab.roundtrip('crash',lab.request('crash'),server_options={'fixture_crash':'PARTIAL'})
            if crash['server_exit']!=73:raise RuntimeError('CRASH_CONTROL_BROKEN')
            value=lab.request('negative')
        elif kind=='filetype':os.link(lab.resource,lab.root/'resource-alias')
        elif kind=='nonce_memory':value['request']['nonce']='positive'
        elif kind=='journal_state':
            from contextlib import closing
            with closing(sqlite3.connect(lab.journal/'operations.sqlite')) as db, db:
                db.execute("UPDATE operations SET state='UNKNOWN'")
        elif kind=='acl':
            before=lab.resource.read_bytes();probe=lab.probe('negative',lab.agent,[(str(lab.resource),'write')])
            result={'positive_ok':positive_ok,'negative_wrote':lab.resource.read_bytes()!=before,
                    'negative':probe,'expected':'OS_DENIAL_AND_UNCHANGED','boundary':kind}
            write(out/'witness.json',result);return result
        else:raise ValueError(kind)
        before=lab.resource.read_bytes()
        # Directory pin failure is an expected fail-closed startup with no client dispatch.
        if kind=='directory_identity':
            try:row=lab.roundtrip('negative',value,container,options,**client_options)
            except RuntimeError as exc:
                if str(exc)!='BROKER_START_FAILED':raise
                row={'name':'negative','response':{'error':str(exc)},'unchanged':lab.resource.read_bytes()==before}
        else:row=lab.roundtrip('negative',value,container,options,**client_options)
        wrote=lab.resource.read_bytes()!=before
        result={'positive_ok':positive_ok,'negative_wrote':wrote,'negative':row,
                'expected':'DENY_AND_UNCHANGED','boundary':kind}
        write(out/'witness.json',result);return result
    finally:lab.close()


def run(out):
    out=out.absolute();out.mkdir(parents=True,exist_ok=True);rows=[];unsupported=[];start=time.perf_counter()
    def record(name,passed,**details):
        row={'name':name,'passed':bool(passed),**details};rows.append(row);print(json.dumps(row),flush=True)
    lab=Lab02(out/'ipc')
    try:
        row=lab.roundtrip('allow');record('allow',allowed(row) and lab.resource.read_bytes()==b'approved:allow')
        receipt=answer(row).get('receipt')
        for name,patch in {'actor_substitution':{'actor':'host'},'wrong_action':{'action':'delete'},
          'wrong_resource':{'resource':'arbitrary/path'},'wrong_scope':{'scope':'arbitrary'},
          'expired':{'expires_at':999},'version':{'policy_version':'unknown'},'missing_evidence':{'evidence':{}},
          'precondition':{'evidence':{'before_sha256':'0'*64}},'untrusted_flag':{'authorized':True},
          'invalid_type':{'nonce':[]}}.items():
            row=lab.roundtrip(name,lab.request(name,**patch));record(name,not allowed(row) and row['unchanged'],status=answer(row).get('status'),reason=answer(row).get('reason'))
        for name,raw in (('malformed',b'{'),('duplicate_field',b'{"schema":0,"schema":1}'),('oversize',b'x'*17000)):
            row=lab.roundtrip(name,raw);record(name,not allowed(row) and row['unchanged'],reason=answer(row).get('reason'))
        row=lab.roundtrip('restart_replay',lab.request('restart_replay',nonce='allow'))
        record('replay_after_restart',row['unchanged'] and answer(row).get('reason')=='REPLAY')
        row=lab.roundtrip('unauthorized_pipe_client',lab.request('unauthorized'),container=lab.other,server_options={'timeout_ms':500})
        record('unauthorized_pipe_client',row['unchanged'] and row['response'].get('winerror')==5,winerror=row['response'].get('winerror'))
        row=lab.roundtrip('idle_client',server_options={'timeout_ms':500},fixture_idle=True)
        server=json.loads((out/'ipc/idle_client.server.json').read_bytes())
        record('timeout_cancellation',row['unchanged'] and 'IPC_TIMEOUT_CANCELLED' in server[0]['response']['reason'])
        # Same state preimage, same nonce, simultaneous processes, one sequential broker.
        request=lab.request('concurrent');before=lab.resource.read_bytes();lab.start('concurrent',connections=2)
        observed={};errors=[]
        def submit(n):
            try:observed[n]=lab.client('concurrent-'+n,request)
            except Exception as exc:errors.append(str(exc))
        threads=[threading.Thread(target=submit,args=(n,)) for n in ('a','b')]
        for t in threads:t.start()
        for t in threads:t.join()
        lab.finish('concurrent');responses=[r.get('response',{}) for r in observed.values()]
        record('concurrent_nonce',not errors and sum(r.get('execution')=='COMMITTED' for r in responses)==1
          and sum(r.get('reason')=='REPLAY' for r in responses)==1 and lab.resource.read_bytes()==b'approved:concurrent',
          decisions=sorted(r.get('reason','missing') for r in responses),errors=errors)
        # Independent verifier runs outside the broker; tampered bytes and resealed scope.
        trusted={'record':receipt,'pin':lab.pin,'head':receipt['sha256'],'principal':lab.agent.principal,'identity':lab.cfg['resource_identity']}
        for name,tamper in (('receipt_valid',False),('receipt_tampered',True)):
            v=copy.deepcopy(trusted)
            if tamper:v['record']['body']['after_sha256']='0'*64
            path=out/(name+'.json');write(path,v)
            cmd=[sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),'guardian/verify_v02.py',str(path)]
            p=subprocess.run(cmd,cwd=ROOT,capture_output=True)
            (out/(name+'.stdout')).write_bytes(p.stdout);(out/(name+'.stderr')).write_bytes(p.stderr)
            write(out/(name+'.command.json'),{'argv':cmd,'exit_code':p.returncode})
            record(name,p.returncode==(1 if tamper else 0))
        # Direct bypass against the new ACL and broker's own access boundaries.
        probes=[(str(lab.resource),op) for op in ('write','delete','rename','hardlink','acl')]
        probes.extend([(str(lab.base.policy_path),'write'),(str(lab.root/'secure'),'rename'),('\\\\?\\'+str(lab.resource),'write')])
        p=subprocess.run(['cmd','/d','/c','mklink','/J',str(lab.root/'alias'),str(lab.root/'secure')],capture_output=True)
        if p.returncode:raise RuntimeError('JUNCTION_UNAVAILABLE')
        probes.append((str(lab.root/'alias/resource.txt'),'write'))
        obs=lab.probe('bypass',lab.agent,probes)
        record('agent_os_bypass',obs['unchanged'] and all(r['result']=='OS_REJECTED' for r in obs['rows']),operations=len(obs['rows']))
        obs=lab.probe('broker_scope',lab.broker,[(str(lab.outside),'read'),(str(lab.outside),'write'),(str(lab.base.policy_path),'write'),(str(lab.resource),'delete'),(str(lab.resource),'acl')])
        record('broker_os_scope',obs['unchanged'] and all(r['result']=='OS_REJECTED' for r in obs['rows']),operations=len(obs['rows']))
        # ACL fault is detected by an actual agent write, not by the gateway verdict.
        lab.acl(lab.resource,broker='GRGW',agent='GRGW')
        obs=lab.probe('acl_weakening',lab.agent,[(str(lab.resource),'write')])
        record('acl_weakening_detected',not obs['unchanged'] and obs['rows'][0]['result']=='SUCCEEDED')
    finally:lab.close()
    for kind in ('envelope_pin','caller_identity','server_identity','policy_pin','resource_identity','directory_identity','enforcement','recovery_gate','filetype','nonce_memory'):
        result=witness(kind,out/kind);record(kind,result['positive_ok'] and not result['negative_wrote'])
    for stage,expected_state,expected_bytes in (('PREPARED','ABORTED',b'initial\n'),('PARTIAL','RECOVERY_REQUIRED',b'approved'),('WRITTEN','RECOVERY_REQUIRED',b'approved:crash'),('COMMITTED','COMMITTED',b'approved:crash')):
        lab=Lab02(out/('crash-'+stage))
        try:
            row=lab.roundtrip('crash',lab.request('crash'),server_options={'fixture_crash':stage})
            actual=lab.resource.read_bytes();row2=lab.roundtrip('restart',lab.request('restart',nonce='crash'))
            states=lab.rows();write(out/('crash-'+stage)/'journal.json',states)
            good_bytes=(actual==b'approved:crash'[:len(b'approved:crash')//2] if stage=='PARTIAL' else actual==expected_bytes)
            record('crash_'+stage,row['server_exit']==73 and good_bytes and row2['unchanged'] and not allowed(row2)
                   and len(states)==1 and states[0]['state']==expected_state,state=states[0]['state'] if states else None,
                   bytes_sha256=digest(actual),restart_reason=answer(row2).get('reason'))
        finally:lab.close()
    lab=Lab02(out/'locking')
    try:
        value=lab.request('locking');lab.start('locking',fixture_pause='PREPARED')
        results={}
        t=threading.Thread(target=lambda:results.update(client=lab.client('locking',value)));t.start()
        deadline=time.monotonic()+4
        while not (lab.journal/'paused.json').exists() and time.monotonic()<deadline:time.sleep(.01)
        if not (lab.journal/'paused.json').exists():raise RuntimeError('BARRIER_NOT_REACHED')
        attacks=[]
        for name,action in [('resource_write',lambda:lab.resource.write_bytes(b'race')),
          ('resource_rename',lambda:lab.resource.rename(lab.root/'moved')),
          ('policy_write',lambda:lab.base.policy_path.write_bytes(b'race')),
          ('parent_rename',lambda:(lab.root/'secure').rename(lab.root/'moved-dir'))]:
            try:action();attacks.append({'name':name,'result':'SUCCEEDED'})
            except OSError as exc:attacks.append({'name':name,'result':'OS_REJECTED','winerror':exc.winerror})
        (lab.journal/'continue').write_bytes(b'continue');t.join();lab.finish('locking')
        write(out/'locking/attacks.json',attacks)
        record('locked_toctou',all(a['result']=='OS_REJECTED' for a in attacks) and lab.resource.read_bytes()==b'approved:locking',operations=len(attacks))
    finally:lab.close()
    lab=Lab02(out/'missing-journal')
    try:
        (lab.journal/'operations.sqlite').unlink();row=lab.roundtrip('missing_journal')
        record('missing_journal',row['unchanged'] and answer(row).get('status')=='UNVERIFIABLE' and not (lab.journal/'operations.sqlite').exists())
    finally:lab.close()
    lab=Lab02(out/'unknown-journal')
    try:
        row=lab.roundtrip('positive');positive=allowed(row)
        from contextlib import closing
        with closing(sqlite3.connect(lab.journal/'operations.sqlite')) as db, db:
            db.execute("UPDATE operations SET state='UNKNOWN'")
        row=lab.roundtrip('unknown_journal')
        record('unknown_journal',positive and row['unchanged'] and answer(row).get('status')=='UNVERIFIABLE')
    finally:lab.close()
    lab=Lab02(out/'symlink')
    try:
        original=lab.root/'original-resource';lab.resource.rename(original)
        try:os.symlink(original,lab.resource)
        except OSError as exc:
            unsupported.append({'name':'file_symlink','status':'NOT_COVERED','winerror':exc.winerror,'reason':'non-elevated symlink fixture unavailable; no privilege requested'})
            original.rename(lab.resource)
        else:
            row=lab.roundtrip('symlink');record('file_symlink',row['unchanged'] and not allowed(row))
    finally:lab.close()
    report={'schema':'guardian.conformance.v02','passed':all(r['passed'] for r in rows),'cases':rows,
      'not_covered':unsupported,'seconds':time.perf_counter()-start,'external_execution':'UNVERIFIABLE','os_scope':'finite Windows laboratory only'}
    write(out/'report.json',report);write(out/'semantic.json',{'cases':rows,'not_covered':unsupported,'external_execution':'UNVERIFIABLE'})
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--witness');a=p.parse_args()
    if a.witness:witness(a.witness,a.out.absolute())
    else:raise SystemExit(not run(a.out)['passed'])
