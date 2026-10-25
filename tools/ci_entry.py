"""Drop an already elevated CI runner to its existing limited token, never elevate.

No accounts, passwords, privilege enabling, UAC changes or existing ACL changes.
If no safe linked token is available the OS replay remains NOT_COVERED and fails.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guardian import windows as win


def main(out,no_mutations=False):
    (ROOT/'build').mkdir(exist_ok=True)
    log=ROOT/'build/ci-launch.json'
    current=win.token_info();safe={k:v for k,v in current.items() if k!='user_sid'}
    record={'initial_token':safe,'policy':'existing non-elevated same-user token only','status':'NOT_COVERED'}
    def save():log.write_bytes(json.dumps(record,indent=2,sort_keys=True).encode()+b'\n')
    args=['tools/validate.py','--out',str(out)]+(['--no-mutations'] if no_mutations else [])
    if not current['elevated']:
        record['mode']='ALREADY_NON_ELEVATED';save()
        code=subprocess.run([sys.executable,'-B',*args],cwd=ROOT).returncode
        record.update(status='EXECUTED',exit_code=code);save();return code
    token=w.HANDLE();linked=w.HANDLE();pi=win.PROCESSINFO();finished=False
    try:
        win.check(win.open_token(win.current(),8,c.byref(token)))
        size=w.DWORD()
        win.check(win.get_token(token,19,c.byref(linked),c.sizeof(linked),c.byref(size)))
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
        win.check(create(linked,1,sys.executable,c.create_unicode_buffer(subprocess.list2cmdline(argv)),4|0x08000000|0x400,env,str(ROOT),c.byref(si),c.byref(pi)))
        observed=win.token_info(pi.hProcess)
        record['limited_process_token']={k:v for k,v in observed.items() if k!='user_sid'}
        record['same_user']=observed['user_sid']==current['user_sid'];save()
        if observed['elevated'] or observed['integrity_sid']!='S-1-16-8192' or not record['same_user']:
            win.api(win.k,'TerminateProcess',w.BOOL,w.HANDLE,w.UINT)(pi.hProcess,99)
            raise RuntimeError('safe limited broker identity not established')
        if win.api(win.k,'ResumeThread',w.DWORD,w.HANDLE)(pi.hThread)==0xffffffff:raise c.WinError(c.get_last_error())
        if win.api(win.k,'WaitForSingleObject',w.DWORD,w.HANDLE,w.DWORD)(pi.hProcess,1800000)!=0:
            win.api(win.k,'TerminateProcess',w.BOOL,w.HANDLE,w.UINT)(pi.hProcess,98);raise TimeoutError('limited validation timeout')
        code=w.DWORD();win.check(win.api(win.k,'GetExitCodeProcess',w.BOOL,w.HANDLE,c.POINTER(w.DWORD))(pi.hProcess,c.byref(code)))
        finished=True
        record.update(mode='EXISTING_LIMITED_TOKEN',status='EXECUTED',exit_code=code.value);save()
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
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--no-mutations',action='store_true');a=p.parse_args()
    raise SystemExit(main(a.out,a.no_mutations))
