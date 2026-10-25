"""Bounded suspended-process diagnostics; never enables a privilege or runs a child."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guardian import windows as win
from tools.ci_tokens import inspect,reduced_token,acceptable
from tools.ci_diagnostics import access
import v04_native as native

class LUID(c.Structure):_fields_=[('low',w.DWORD),('high',w.LONG)]
class USTRING(c.Structure):_fields_=[('length',w.USHORT),('maximum',w.USHORT),('buffer',w.LPWSTR)]
class SESSION(c.Structure):
    _fields_=[('size',w.ULONG),('id',LUID),('user',USTRING),('domain',USTRING),('package',USTRING),('logon_type',w.ULONG),('session',w.ULONG),('sid',win.P)]

def logon(token):
    stats=native.token_query(token,10);auth=LUID.from_buffer_copy(stats.raw[8:16]);out=c.POINTER(SESSION)()
    dll=c.WinDLL('secur32',use_last_error=True)
    status=win.api(dll,'LsaGetLogonSessionData',w.LONG,c.POINTER(LUID),c.POINTER(c.POINTER(SESSION)))(c.byref(auth),c.byref(out))
    r={'ntstatus':status,'authentication_id':f'{auth.high & 0xffffffff:08x}:{auth.low:08x}'}
    if status==0 and out:
        try:r.update(logon_type=out.contents.logon_type,session_id=out.contents.session,user_sha256=hashlib.sha256(native.sid(out.contents.sid).encode()).hexdigest())
        finally:win.api(dll,'LsaFreeReturnBuffer',w.LONG,win.P)(out)
    return r

def duplicate(token,kind=1,rights=0x02000000):
    other=w.HANDLE();win.check(win.api(win.a,'DuplicateTokenEx',w.BOOL,w.HANDLE,w.DWORD,win.P,c.c_int,c.c_int,c.POINTER(w.HANDLE))(
        token,rights,None,2,kind,c.byref(other)));return other

def probe_access(token):
    other=None;rows=[]
    try:
        other=duplicate(token,2)
        win.check(win.api(win.a,'SetThreadToken',w.BOOL,win.P,w.HANDLE)(None,other))
        observed=native.thread()
        for label,path,rights,flags in [('python',sys.executable,0xa0000000,0),('cwd',str(ROOT),0x80,0x02000000)]:
            h=win.api(win.k,'CreateFileW',w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,win.P,w.DWORD,w.DWORD,w.HANDLE)(path,rights,7,None,3,flags,None)
            ok=h!=c.c_void_p(-1).value;rows.append({'label':label,'opened':ok,'winerror':0 if ok else c.get_last_error()})
            if ok:win.close(h)
        return {'thread':observed,'objects':rows}
    except OSError as e:return {'not_covered':str(e),'winerror':e.winerror}
    finally:
        if not win.api(win.a,'RevertToSelf',w.BOOL)():os._exit(91)
        if other:win.close(other)

def run(out):
    current=w.HANDLE();reduced=None;expanded=None;out.parent.mkdir(parents=True,exist_ok=True)
    win.check(win.open_token(win.current(),0x8b,c.byref(current)))
    record={'schema':'guardian.windows-ci-probe.v04','platform':platform.platform(),'python':sys.version,'attempts':[],
      'privileges_enabled':False,'children_resumed':False,'enforcement':'NOT_COVERED'}
    def save():out.write_bytes(json.dumps(record,sort_keys=True,indent=2).encode()+b'\n')
    try:
        parent=inspect(current);record['parent']=parent;record['parent_logon']=logon(current);save()
        if not parent['elevated']:
            record['attempts_not_run']='existing non-elevated context; no hosted privileged caller available';save();return record
        if not parent['privilege_attributes'].get('SeImpersonatePrivilege',{}).get('enabled'):
            record['attempts_not_run']='SeImpersonatePrivilege not already enabled';save();return record
        reduced=reduced_token(current);details=inspect(reduced)
        if not acceptable(details,parent['user_sha256']):raise RuntimeError('REDUCTION_CONTROL_BROKEN')
        record['reduced']=details;record['reduced_logon']=logon(reduced);record['reduced_access']=access(reduced)
        record['readonly_object_access']=probe_access(reduced);record['thread_after']=native.thread();save()
        expanded=duplicate(reduced);record['expanded_token']=inspect(expanded);record['expanded_access']=access(expanded)
        if not acceptable(record['expanded_token'],parent['user_sha256']):raise RuntimeError('DUPLICATE_CONTROL_BROKEN')
        env=c.create_unicode_buffer('SystemRoot='+os.environ['SystemRoot']+'\0\0')
        create=win.api(win.a,'CreateProcessWithTokenW',w.BOOL,w.HANDLE,w.DWORD,w.LPCWSTR,w.LPWSTR,w.DWORD,win.P,w.LPCWSTR,c.POINTER(win.STARTUPINFO),c.POINTER(win.PROCESSINFO))
        candidates=[('existing',reduced),('maximum_allowed_handle',expanded)];bounded=[]
        # Each is a new copy of the same reduced primary token. Compare narrow
        # handle rights while holding logon identity, privileges and flags fixed.
        for rights in (0x8b,0x8f,0x18b,0x9b,0xab,0xcb,0x2008b):
            token=duplicate(reduced,rights=rights);bounded.append(token);candidates.append(('duplicate_'+hex(rights),token))
        for name,token in candidates:
            for flags in (4|0x400|0x08000000,):
                si=win.STARTUPINFO();si.cb=c.sizeof(si);pi=win.PROCESSINFO()
                ok=create(token,0,sys.executable,c.create_unicode_buffer('"'+sys.executable+'" -B -c "pass"'),flags,env,str(ROOT),c.byref(si),c.byref(pi))
                row={'token_handle':name,'granted_access':access(token),'flags':hex(flags),'created_suspended':bool(ok),'winerror':0 if ok else c.get_last_error(),'resumed':False}
                try:
                    if ok:
                        row['actual_child']=native.process(pi.dwProcessId)
                        child=w.HANDLE();win.check(win.open_token(pi.hProcess,8,c.byref(child)))
                        try:row['child_acceptable']=acceptable(inspect(child),parent['user_sha256'])
                        finally:win.close(child)
                finally:
                    if pi.hProcess:
                        win.check(win.api(win.k,'TerminateProcess',w.BOOL,w.HANDLE,w.UINT)(pi.hProcess,97))
                        row['termination_wait']=win.api(win.k,'WaitForSingleObject',w.DWORD,w.HANDLE,w.DWORD)(pi.hProcess,5000)
                    for h in (pi.hThread,pi.hProcess):
                        if h:win.close(h)
                record['attempts'].append(row);save()
        for token in bounded:win.close(token)
        return record
    finally:
        for h in (expanded,reduced,current):
            if h:win.close(h)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();run(a.out)
