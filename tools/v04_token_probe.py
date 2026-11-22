"""Disposable same-AppContainer named-pipe diagnostic; no resource authority."""
import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import sys
import threading
import uuid
from guardian import ipc,windows as win
import v04_native as native

def run(out):
    before=native.process();rows=[]
    for requested in (1,2,3):
        name='\\\\.\\pipe\\LOCAL\\GuardianSame-'+uuid.uuid4().hex
        pipe=ipc.Server(name,before['appcontainer_sid'],before['appcontainer_sid'],win.token_info()['user_sid'])
        result={}
        def client():
            h=None
            try:
                h=win.api(win.k,'CreateFileW',w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,win.P,w.DWORD,w.DWORD,w.HANDLE)(name,ipc.CLIENT_ACCESS,0,None,3,0x40000000|0x100000|(requested<<16),None)
                if h==c.c_void_p(-1).value:h=None;raise c.WinError(c.get_last_error())
                ipc.io(h,'write',b'probe');ipc.io(h,'read');result['completed']=True
            except Exception as e:result['error']=repr(e)
            finally:
                if h:win.close(h)
        t=threading.Thread(target=client);t.start()
        try:
            ipc.io(pipe.handle,'connect');ipc.io(pipe.handle,'read')
            win.check(win.api(win.a,'ImpersonateNamedPipeClient',w.BOOL,w.HANDLE)(pipe.handle))
            try:
                observed=native.thread()
                handle=win.api(win.k,'CreateFileW',w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,win.P,w.DWORD,w.DWORD,w.HANDLE)(str(out.parent/'token-io.txt'),0x40000000,7,None,2,0,None)
                token_io={'opened':handle!=c.c_void_p(-1).value,'winerror':0 if handle!=c.c_void_p(-1).value else c.get_last_error()}
                if token_io['opened']:win.close(handle)
            finally:win.check(win.api(win.a,'RevertToSelf',w.BOOL)())
            try:identity=ipc.authenticate(pipe.handle,before['appcontainer_sid'],before['user_sha256']);decision={'accepted':True,'identity':identity}
            except PermissionError as e:decision={'accepted':False,'reason':str(e)}
            after=native.thread();ipc.io(pipe.handle,'write',b'done');t.join(4)
            rows.append({'requested':requested,'observed':observed,'token_io':token_io,'decision':decision,'thread_after':after,'client':result,'thread_finished':not t.is_alive()})
        finally:pipe.close();t.join(4)
    out.write_bytes(json.dumps({'schema':'guardian.same-container-pipe.v04','process':before,'rows':rows,'resource_execution':False},indent=2,sort_keys=True).encode()+b'\n')

if __name__=='__main__':
    try:run(Path(sys.argv[1]))
    except Exception:
        import traceback
        Path(sys.argv[1]).write_bytes(json.dumps({'control_broken':traceback.format_exc()}).encode()+b'\n')
        raise
