"""Bounded hosted startup observations; no privilege/desktop/ACL changes."""
import argparse,ctypes as c,hashlib,json,os,subprocess,sys,time
from ctypes import wintypes as w
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guardian import windows as win
from tools.ci_tokens import reduced_token,inspect,acceptable

def desktop_access(token):
    user=c.WinDLL('user32',use_last_error=True)
    station=win.api(user,'GetProcessWindowStation',w.HANDLE)()
    desktop=win.api(user,'GetThreadDesktop',w.HANDLE,w.DWORD)(win.api(win.k,'GetCurrentThreadId',w.DWORD)())
    def name(handle):
        size=w.DWORD();buf=c.create_unicode_buffer(1024)
        win.check(win.api(user,'GetUserObjectInformationW',w.BOOL,w.HANDLE,c.c_int,win.P,w.DWORD,c.POINTER(w.DWORD))(handle,2,buf,c.sizeof(buf),c.byref(size)));return buf.value
    result={'station':name(station),'desktop':name(desktop),'acl_changes':False};other=w.HANDLE()
    try:
        win.check(win.api(win.a,'DuplicateTokenEx',w.BOOL,w.HANDLE,w.DWORD,win.P,c.c_int,c.c_int,c.POINTER(w.HANDLE))(token,0xc,None,2,2,c.byref(other)))
        win.check(win.api(win.a,'SetThreadToken',w.BOOL,win.P,w.HANDLE)(None,other))
        for label,api,args,close in (
            ('station_read',win.api(user,'OpenWindowStationW',w.HANDLE,w.LPCWSTR,w.BOOL,w.DWORD),(result['station'],False,3),'CloseWindowStation'),
            ('desktop_read',win.api(user,'OpenDesktopW',w.HANDLE,w.LPCWSTR,w.DWORD,w.BOOL,w.DWORD),(result['desktop'],0,False,1),'CloseDesktop')):
            handle=api(*args);result[label]={'opened':bool(handle),'winerror':0 if handle else c.get_last_error()}
            if handle:win.check(win.api(user,close,w.BOOL,w.HANDLE)(handle))
    finally:
        if not win.api(win.a,'RevertToSelf',w.BOOL)():os._exit(91)
        if other:win.close(other)
    return result

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
        record['desktop_access']=desktop_access(launch);save()
        snippet=''
        candidates=[('cmd',[os.environ['COMSPEC'],'/d','/q','/c','exit','0'],False),
                    ('python-isolated',[sys.executable,'-I','-S','-B','-c',snippet],False),
                    ('python-inherited-env',[sys.executable,'-I','-S','-B','-c',snippet],True),
                    ('cmd-current-desktop',[os.environ['COMSPEC'],'/d','/q','/c','exit','0'],False),
                    ('python-current-desktop',[sys.executable,'-I','-S','-B','-c',snippet],False)]
        create=win.api(win.a,'CreateProcessWithTokenW',w.BOOL,w.HANDLE,w.DWORD,w.LPCWSTR,w.LPWSTR,w.DWORD,win.P,w.LPCWSTR,c.POINTER(win.STARTUPINFO),c.POINTER(win.PROCESSINFO))
        for name,argv,inherited in candidates:
            pi=win.PROCESSINFO();si=win.STARTUPINFO();si.cb=c.sizeof(si);row={'name':name,'argv':argv,'inherited_environment':inherited};started=time.perf_counter()
            marker=out.with_suffix('.'+name+'.child.json').absolute()
            if marker.exists():raise ValueError('fresh per-attempt marker required')
            if name.startswith('python'):argv[-1]='import pathlib;pathlib.Path('+repr(str(marker))+').write_bytes(b"started\\n")'
            if name.endswith('current-desktop'):si.lpDesktop=record['desktop_access']['station']+'\\'+record['desktop_access']['desktop']
            row['requested_desktop']=si.lpDesktop
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
