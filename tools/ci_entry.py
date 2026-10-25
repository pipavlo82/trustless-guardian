"""Reduce an already elevated runner; never elevate or enable privileges.

No accounts, passwords, privilege enabling, UAC changes or existing ACL changes.
If neither a linked nor an explicitly reduced token passes inspection, fail closed.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess
import sys
import hashlib

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guardian import windows as win


def main(out,no_mutations=False,profile='v0'):
    (ROOT/'build').mkdir(exist_ok=True)
    log=ROOT/'build/ci-launch.json'
    current=win.token_info();safe={k:v for k,v in current.items() if k!='user_sid'}
    record={'initial_token':safe,'policy':'non-elevated same-user token; existing linked or ephemeral LUA reduction','status':'NOT_COVERED','profile':profile,'stage':'INITIAL_TOKEN'}
    def save():log.write_bytes(json.dumps(record,indent=2,sort_keys=True).encode()+b'\n')
    args=['tools/validate_v02.py' if profile=='v02' else 'tools/validate.py','--out',str(out)]+(['--no-mutations'] if no_mutations else [])
    if not current['elevated']:
        record['mode']='ALREADY_NON_ELEVATED';save()
        code=subprocess.run([sys.executable,'-B',*args],cwd=ROOT).returncode
        record.update(status='EXECUTED',exit_code=code);save();return code
    token=w.HANDLE();linked=w.HANDLE();pi=win.PROCESSINFO();finished=False
    try:
        record['stage']='OPEN_CURRENT_TOKEN';save()
        win.check(win.open_token(win.current(),0x8b,c.byref(token)))
        size=w.DWORD()
        record['stage']='QUERY_EXISTING_LINKED_TOKEN';save()
        reduced=False
        if not win.get_token(token,19,c.byref(linked),c.sizeof(linked),c.byref(size)):
            error=c.get_last_error()
            record['linked_token_error']=error;save()
            if error!=1312:raise c.WinError(error)
            from tools.ci_tokens import reduced_token,inspect,acceptable
            record['stage']='CREATE_EPHEMERAL_REDUCED_TOKEN';save()
            linked=reduced_token(token);reduced=True
            observed=inspect(linked);record['reduced_token']=observed;save()
            if not acceptable(observed,hashlib.sha256(current['user_sid'].encode()).hexdigest()):
                raise RuntimeError('ephemeral reduction failed security predicates')
        elevated=w.DWORD()
        win.check(win.get_token(linked,20,c.byref(elevated),c.sizeof(elevated),c.byref(size)))
        if elevated.value:raise RuntimeError('linked token is elevated; refusing')
        stdout=ROOT/'build/ci-launch.stdout';stderr=ROOT/'build/ci-launch.stderr'
        snippet=('import sys,runpy;sys.stdout=open('+repr(str(stdout))+",'w',encoding='utf-8',newline='\\n');"
          +'sys.stderr=open('+repr(str(stderr))+",'w',encoding='utf-8',newline='\\n');"
          +'sys.argv='+repr(args)+";runpy.run_path('tools/validate.py',run_name='__main__')")
        argv=[sys.executable,'-B','-c',snippet]
        si=win.STARTUPINFO();si.cb=c.sizeof(si)
        create=win.api(win.a,'CreateProcessWithTokenW',w.BOOL,w.HANDLE,w.DWORD,w.LPCWSTR,w.LPWSTR,w.DWORD,win.P,w.LPCWSTR,c.POINTER(win.STARTUPINFO),c.POINTER(win.PROCESSINFO))
        names=['SystemRoot','WINDIR','SystemDrive','USERPROFILE','LOCALAPPDATA','APPDATA','ProgramFiles','ProgramData','COMSPEC','PATH']
        values={name:os.environ[name] for name in names if name in os.environ}
        values.update(TEMP=os.environ.get('TEMP',str(ROOT/'build')),TMP=os.environ.get('TMP',str(ROOT/'build')),PYTHONDONTWRITEBYTECODE='1')
        env=c.create_unicode_buffer('\0'.join(k+'='+values[k] for k in sorted(values,key=str.upper))+'\0\0')
        record['stage']='CREATE_LIMITED_PROCESS';save()
        # No new logon/profile; parent already has its profile. API may require an
        # existing SeImpersonatePrivilege, but this launcher never enables it.
        win.check(create(linked,0,sys.executable,c.create_unicode_buffer(subprocess.list2cmdline(argv)),4|0x08000000|0x400,env,str(ROOT),c.byref(si),c.byref(pi)))
        observed=win.token_info(pi.hProcess)
        record['limited_process_token']={k:v for k,v in observed.items() if k!='user_sid'}
        record['same_user']=observed['user_sid']==current['user_sid'];save()
        if observed['elevated'] or observed['integrity_sid']!='S-1-16-8192' or not record['same_user']:
            win.api(win.k,'TerminateProcess',w.BOOL,w.HANDLE,w.UINT)(pi.hProcess,99)
            raise RuntimeError('safe limited broker identity not established')
        if reduced:
            child_token=w.HANDLE();win.check(win.open_token(pi.hProcess,8,c.byref(child_token)))
            try:child=inspect(child_token)
            finally:win.close(child_token)
            record['reduced_child_token']=child;save()
            if not acceptable(child,hashlib.sha256(current['user_sid'].encode()).hexdigest()):
                raise RuntimeError('created child did not preserve reduction')
        if win.api(win.k,'ResumeThread',w.DWORD,w.HANDLE)(pi.hThread)==0xffffffff:raise c.WinError(c.get_last_error())
        if win.api(win.k,'WaitForSingleObject',w.DWORD,w.HANDLE,w.DWORD)(pi.hProcess,1800000)!=0:
            win.api(win.k,'TerminateProcess',w.BOOL,w.HANDLE,w.UINT)(pi.hProcess,98);raise TimeoutError('limited validation timeout')
        code=w.DWORD();win.check(win.api(win.k,'GetExitCodeProcess',w.BOOL,w.HANDLE,c.POINTER(w.DWORD))(pi.hProcess,c.byref(code)))
        finished=True
        record.update(mode='EPHEMERAL_REDUCED_TOKEN' if reduced else 'EXISTING_LIMITED_TOKEN',status='EXECUTED',exit_code=code.value);save()
        for file,stream in ((stdout,sys.stdout),(stderr,sys.stderr)):
            if file.exists():stream.write(file.read_text(encoding='utf-8'))
        return code.value
    except (OSError,RuntimeError,TimeoutError) as exc:
        record['failure']=type(exc).__name__+': '+str(exc);save();print(json.dumps(record));return 2
    finally:
        if pi.hProcess and not finished:win.api(win.k,'TerminateProcess',w.BOOL,w.HANDLE,w.UINT)(pi.hProcess,98)
        for handle in (pi.hThread,pi.hProcess,linked,token):
            if handle:win.close(handle)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--no-mutations',action='store_true');p.add_argument('--profile',choices=['v0','v02'],default='v0');a=p.parse_args()
    raise SystemExit(main(a.out,a.no_mutations,a.profile))
