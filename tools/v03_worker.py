"""Trusted disposable fault harness; no fault switches in the IPC request schema."""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
from guardian import windows as win, ipc
from guardian.hardened import HardenedBroker, refusal
from guardian.policy import canonical, digest, parse
from v02_worker import save, probe


def thread_token():
    token=w.HANDLE()
    ok=win.api(win.a,'OpenThreadToken',w.BOOL,w.HANDLE,w.DWORD,w.BOOL,c.POINTER(w.HANDLE))(
        win.api(win.k,'GetCurrentThread',w.HANDLE)(),8,True,c.byref(token))
    error=0 if ok else c.get_last_error()
    if token:win.close(token)
    return {'present':bool(ok),'winerror':error}


def pipe_descriptor(handle):
    sd=win.P();text=w.LPWSTR()
    code=win.api(win.a,'GetSecurityInfo',w.DWORD,w.HANDLE,c.c_int,w.DWORD,win.P,win.P,win.P,win.P,c.POINTER(win.P))(
        handle,6,4,None,None,None,None,c.byref(sd))
    if code:raise c.WinError(code)
    try:
        win.check(win.api(win.a,'ConvertSecurityDescriptorToStringSecurityDescriptorW',w.BOOL,win.P,w.DWORD,w.DWORD,c.POINTER(w.LPWSTR),win.P)(sd,1,4,c.byref(text),None))
        return text.value
    finally:
        if text:win.local_free(text)
        win.local_free(sd)


def server(cfg):
    out=Path(cfg['root'])/'journal';prefix=cfg.get('fixture_channel','');rows=[];locks=[]
    broker=HardenedBroker(cfg)
    pipe=ipc.Server(cfg['pipe_local'],cfg['broker_sid'],cfg.get('fixture_pipe_sid',cfg['agent_sid']),win.token_info()['user_sid'])
    save(out/(prefix+'ready.json'),{'pid':os.getpid(),'dacl':pipe_descriptor(pipe.handle)})
    def fault(stage,resource,raw):
        if cfg.get('fixture_commit_lock') and stage=='WRITTEN':
            db=sqlite3.connect(out/'operations.sqlite',timeout=.25);db.execute('BEGIN IMMEDIATE');locks.append(db)
        if cfg.get('fixture_crash')=='PARTIAL' and stage=='PREPARED':
            resource.replace(raw[:max(1,len(raw)//2)]);os._exit(73)
        if cfg.get('fixture_crash')==stage:os._exit(73)
        if cfg.get('fixture_raise')==stage:raise OSError('TRUSTED_LAB_FAULT')
        if cfg.get('fixture_pause')==stage:
            save(out/(prefix+'paused.json'),{'stage':stage})
            until=time.monotonic()+8
            while not (out/(prefix+'continue')).exists() and time.monotonic()<until:time.sleep(.01)
            if not (out/(prefix+'continue')).exists():raise TimeoutError('LAB_BARRIER')
    try:
        for _ in range(cfg.get('connections',1)):
            connected=False;identity=None
            try:
                ipc.io(pipe.handle,'connect',timeout_ms=cfg.get('timeout_ms',1800));connected=True
                raw=ipc.io(pipe.handle,'read',timeout_ms=cfg.get('timeout_ms',1800))
                identity=ipc.authenticate(pipe.handle,cfg['agent_sid'],cfg['user_sha256'])
                response=broker.execute(raw,identity['appcontainer_sid'],cfg.get('fixture_time',1000),fault)
                row={'response':response,'identity':identity,'request_sha256':digest(raw)}
            except Exception as exc:
                response=refusal(type(exc).__name__+': '+str(exc),'UNVERIFIABLE' if isinstance(exc,OSError) else 'REFUTED')
                row={'response':response,'transport_error':True}
            finally:
                for db in locks:db.rollback();db.close()
                locks.clear()
            row['thread_after_auth']=thread_token();rows.append(row);save(out/(prefix+'server.json'),rows)
            if connected:
                try:
                    ipc.io(pipe.handle,'write',canonical(response),timeout_ms=700)
                    ipc.io(pipe.handle,'read',timeout_ms=700)
                except (OSError,TimeoutError,ValueError):pass
                win.check(win.api(win.k,'DisconnectNamedPipe',w.BOOL,w.HANDLE)(pipe.handle))
    finally:pipe.close();broker.close()


def client(cfg):
    out=Path(cfg['out']);(out/'scratch').write_bytes(b'positive');result={'completed':True};h=None
    try:
        level=cfg.get('fixture_sqos',1);rights=cfg.get('fixture_rights',ipc.CLIENT_ACCESS)
        if cfg.get('fixture_pipe_instance'):
            h=win.api(win.k,'CreateNamedPipeW',w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,win.P)(
                cfg['pipe'],3|0x40000000,4|2|8,1,16384,16384,3000,None)
            if h==c.c_void_p(-1).value:h=None;raise c.WinError(c.get_last_error())
            result['pipe_instance_created']=True
            return
        if 'fixture_sqos' in cfg or 'fixture_rights' in cfg:
            h=win.api(win.k,'CreateFileW',w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,win.P,w.DWORD,w.DWORD,w.HANDLE)(
                cfg['pipe'],rights,0,None,3,0x40000000|0x100000|(level<<16),None)
            if h==c.c_void_p(-1).value:h=None;raise c.WinError(c.get_last_error())
            mode=w.DWORD(2);win.check(win.api(win.k,'SetNamedPipeHandleState',w.BOOL,w.HANDLE,c.POINTER(w.DWORD),win.P,win.P)(h,c.byref(mode),None,None))
        else:h=ipc.connect(cfg['pipe'],cfg['server_pid'])
        raw=bytes.fromhex(cfg['raw_hex'])
        if cfg.get('fixture_fragment'):
            ipc.io(h,'write',raw[:len(raw)//2]);ipc.io(h,'write',raw[len(raw)//2:])
        else:ipc.io(h,'write',raw)
        if cfg.get('fixture_drop_response'):result['dropped_response']=True
        else:
            result['response']=parse(ipc.io(h,'read'));ipc.io(h,'write',b'ACK')
    except Exception as exc:result.update(error=type(exc).__name__+': '+str(exc),winerror=getattr(exc,'winerror',None))
    finally:
        if h:win.close(h)
        save(out/'client.json',result)


if __name__=='__main__':
    cfg=json.loads(Path(sys.argv[1]).read_bytes())
    try:{'server':server,'client':client,'probe':probe}[cfg['role']](cfg)
    except Exception as exc:
        save(Path(cfg['root'])/'journal'/(cfg.get('fixture_channel','')+'fatal.json'),{'error':repr(exc)})
        raise
