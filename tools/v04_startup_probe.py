"""Bounded hosted startup observations; no privilege/desktop/ACL changes."""
import argparse,ctypes as c,hashlib,json,os,subprocess,sys,time
from ctypes import wintypes as w
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guardian import windows as win
from tools.ci_tokens import reduced_token,inspect,acceptable

def run(out):
    out.parent.mkdir(parents=True,exist_ok=True);current=w.HANDLE();reduced=None;launch=w.HANDLE()
    record={'schema':'guardian.startup-probe.v04','attempts':[],'privileges_enabled':False,'enforcement':'NOT_COVERED'}
    def save():out.write_bytes(json.dumps(record,sort_keys=True,indent=2).encode()+b'\n')
    win.check(win.open_token(win.current(),0x8b,c.byref(current)))
    try:
        parent=inspect(current);record['parent']=parent
        if not parent['elevated']:
            record['not_covered']='requires already elevated hosted caller';save();return
        if not parent['privilege_attributes'].get('SeImpersonatePrivilege',{}).get('enabled'):
            record['not_covered']='SeImpersonatePrivilege not already enabled';save();return
        reduced=reduced_token(current)
        win.check(win.api(win.a,'DuplicateTokenEx',w.BOOL,w.HANDLE,w.DWORD,win.P,c.c_int,c.c_int,c.POINTER(w.HANDLE))(reduced,0x18b,None,2,1,c.byref(launch)))
        record['launch_token']=inspect(launch)
        if not acceptable(record['launch_token'],parent['user_sha256']):raise RuntimeError('TOKEN_CONTROL_BROKEN')
        marker=out.with_suffix('.child.json').absolute()
        if marker.exists():raise ValueError('fresh marker required')
        snippet='import pathlib;pathlib.Path('+repr(str(marker))+').write_bytes(b"started\\n")'
        candidates=[('cmd',[os.environ['COMSPEC'],'/d','/q','/c','exit','0'],False),
                    ('python-isolated',[sys.executable,'-I','-S','-B','-c',snippet],False),
                    ('python-inherited-env',[sys.executable,'-I','-S','-B','-c',snippet],True)]
        create=win.api(win.a,'CreateProcessWithTokenW',w.BOOL,w.HANDLE,w.DWORD,w.LPCWSTR,w.LPWSTR,w.DWORD,win.P,w.LPCWSTR,c.POINTER(win.STARTUPINFO),c.POINTER(win.PROCESSINFO))
        for name,argv,inherited in candidates:
            pi=win.PROCESSINFO();si=win.STARTUPINFO();si.cb=c.sizeof(si);row={'name':name,'argv':argv,'inherited_environment':inherited};started=time.perf_counter()
            values={k:os.environ[k] for k in ('SystemRoot','WINDIR','SystemDrive','USERPROFILE','LOCALAPPDATA','APPDATA','ProgramFiles','ProgramData','COMSPEC','PATH','TEMP','TMP') if k in os.environ}
            env=c.create_unicode_buffer('\0'.join(k+'='+values[k] for k in sorted(values,key=str.upper))+'\0\0')
            try:
                win.check(create(launch,0,argv[0],c.create_unicode_buffer(subprocess.list2cmdline(argv)),4|0x400|0x08000000,None if inherited else env,str(ROOT),c.byref(si),c.byref(pi)))
                child=w.HANDLE();win.check(win.open_token(pi.hProcess,8,c.byref(child)))
                try:row['child_token']=inspect(child)
                finally:win.close(child)
                if not acceptable(row['child_token'],parent['user_sha256']):raise RuntimeError('CHILD_CONTROL_BROKEN')
                row['resume_previous_count']=win.api(win.k,'ResumeThread',w.DWORD,w.HANDLE)(pi.hThread)
                row['wait']=win.api(win.k,'WaitForSingleObject',w.DWORD,w.HANDLE,w.DWORD)(pi.hProcess,10000)
                code=w.DWORD();win.check(win.api(win.k,'GetExitCodeProcess',w.BOOL,w.HANDLE,c.POINTER(w.DWORD))(pi.hProcess,c.byref(code)));row['exit_code']=code.value
                row['marker']=marker.read_text() if marker.exists() else None
                query='Get-Process -Id '+str(pi.dwProcessId)+' -ErrorAction Stop | ForEach-Object { $_.Threads | Select-Object Id,ThreadState,WaitReason } | ConvertTo-Json'
                if row['wait']!=0:
                    p=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',query],capture_output=True,timeout=10)
                    row['thread_query']={'exit_code':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')}
            except Exception as e:row['error']=repr(e)
            finally:
                if pi.hProcess:
                    win.api(win.k,'TerminateProcess',w.BOOL,w.HANDLE,w.UINT)(pi.hProcess,97)
                    row['termination_wait']=win.api(win.k,'WaitForSingleObject',w.DWORD,w.HANDLE,w.DWORD)(pi.hProcess,5000)
                for handle in (pi.hThread,pi.hProcess):
                    if handle:win.close(handle)
            row['seconds']=time.perf_counter()-started;record['attempts'].append(row);save()
    finally:
        for handle in (launch,reduced,current):
            if handle:win.close(handle)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();run(a.out)
