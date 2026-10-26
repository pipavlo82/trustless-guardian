"""Small Win32 boundary. Operates only on explicitly created disposable roots."""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import subprocess

if os.name != 'nt':
    raise ImportError('Windows enforcement is NOT_COVERED on this platform')

k = c.WinDLL('kernel32', use_last_error=True)
a = c.WinDLL('advapi32', use_last_error=True)
u = c.WinDLL('userenv', use_last_error=True)
P = c.c_void_p
SIZE = c.c_size_t


def api(dll, name, restype, *args):
    f = getattr(dll, name); f.restype = restype; f.argtypes = list(args); return f


close = api(k, 'CloseHandle', w.BOOL, w.HANDLE)
local_free = api(k, 'LocalFree', P, P)
current = api(k, 'GetCurrentProcess', w.HANDLE)
open_token = api(a, 'OpenProcessToken', w.BOOL, w.HANDLE, w.DWORD, c.POINTER(w.HANDLE))
get_token = api(a, 'GetTokenInformation', w.BOOL, w.HANDLE, c.c_int, P, w.DWORD, c.POINTER(w.DWORD))
sid_text = api(a, 'ConvertSidToStringSidW', w.BOOL, P, c.POINTER(w.LPWSTR))
create_profile = api(u, 'CreateAppContainerProfile', c.c_long, w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, P, w.DWORD, c.POINTER(P))
delete_profile = api(u, 'DeleteAppContainerProfile', c.c_long, w.LPCWSTR)
free_sid = api(a, 'FreeSid', P, P)


def check(ok):
    if not ok: raise c.WinError(c.get_last_error())


def sid_string(sid):
    text = w.LPWSTR(); check(sid_text(sid, c.byref(text)))
    try: return text.value
    finally: local_free(text)


def token_info(process=None):
    token = w.HANDLE(); check(open_token(process or current(), 8, c.byref(token)))
    def query(kind):
        size = w.DWORD(); get_token(token, kind, None, 0, c.byref(size))
        buf = c.create_string_buffer(size.value); check(get_token(token, kind, buf, size, c.byref(size))); return buf
    try:
        user = query(1); integrity = query(25); app = query(31)
        ptr = c.cast(app, c.POINTER(P))[0]
        return {'user_sid':sid_string(c.cast(user,c.POINTER(P))[0]),
                'integrity_sid':sid_string(c.cast(integrity,c.POINTER(P))[0]),
                'appcontainer':bool(c.cast(query(29),c.POINTER(w.DWORD))[0]),
                'appcontainer_sid':sid_string(ptr) if ptr else None,
                'elevated':bool(c.cast(query(20),c.POINTER(w.DWORD))[0]),
                'capability_count':int(c.cast(query(30),c.POINTER(w.DWORD))[0])}
    finally: close(token)


def safe_path(root, path):
    root, path = Path(root).absolute(), Path(path).absolute()
    if path != root and root not in path.parents: raise ValueError('outside disposable root')
    if not root.name.startswith('guardian-lab-'): raise ValueError('not a Guardian disposable root')
    part = path
    while part != root.parent:
        if part.exists() and part.lstat().st_file_attributes & 0x400: raise ValueError('reparse ACL target')
        part = part.parent
    return path


def acl(root, path, app_sid, writable=False):
    path = safe_path(root,path)
    user = token_info()['user_sid']
    rights = 'FA' if writable else 'GRGX'
    sddl = f'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})(A;OICI;{rights};;;{app_sid})'
    convert = api(a,'ConvertStringSecurityDescriptorToSecurityDescriptorW',w.BOOL,w.LPCWSTR,w.DWORD,c.POINTER(P),P)
    set_security = api(a,'SetFileSecurityW',w.BOOL,w.LPCWSTR,w.DWORD,P)
    sd=P(); check(convert(sddl,1,c.byref(sd),None))
    try: check(set_security(str(path),4|0x80000000,sd))
    finally:local_free(sd)
    return sddl


def low_label(root,path):
    path=safe_path(root,path)
    # Only a disposable object label; no system setting or existing user ACL changes.
    p=subprocess.run(['icacls',str(path),'/setintegritylevel','(OI)(CI)L' if path.is_dir() else 'L'],capture_output=True)
    if p.returncode:raise OSError(p.stderr.decode(errors='replace'))
    return {'exit_code':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')}


class STARTUPINFO(c.Structure):
    _fields_=[('cb',w.DWORD),('lpReserved',w.LPWSTR),('lpDesktop',w.LPWSTR),('lpTitle',w.LPWSTR),
              ('dwX',w.DWORD),('dwY',w.DWORD),('dwXSize',w.DWORD),('dwYSize',w.DWORD),
              ('dwXCountChars',w.DWORD),('dwYCountChars',w.DWORD),('dwFillAttribute',w.DWORD),
              ('dwFlags',w.DWORD),('wShowWindow',w.WORD),('cbReserved2',w.WORD),('lpReserved2',P),
              ('hStdInput',w.HANDLE),('hStdOutput',w.HANDLE),('hStdError',w.HANDLE)]


class STARTUPINFOEX(c.Structure):
    _fields_=[('StartupInfo',STARTUPINFO),('lpAttributeList',P)]


class PROCESSINFO(c.Structure):
    _fields_=[('hProcess',w.HANDLE),('hThread',w.HANDLE),('dwProcessId',w.DWORD),('dwThreadId',w.DWORD)]


class CAPABILITIES(c.Structure):
    _fields_=[('AppContainerSid',P),('Capabilities',P),('CapabilityCount',w.DWORD),('Reserved',w.DWORD)]


class BASIC_LIMIT(c.Structure):
    _fields_=[('process_time',c.c_longlong),('job_time',c.c_longlong),('flags',w.DWORD),
              ('min_ws',SIZE),('max_ws',SIZE),('active_processes',w.DWORD),('affinity',SIZE),
              ('priority',w.DWORD),('scheduling',w.DWORD)]


class EXTENDED_LIMIT(c.Structure):
    _fields_=[('basic',BASIC_LIMIT),('io',c.c_ulonglong*6),('process_memory',SIZE),('job_memory',SIZE),('peak_process',SIZE),('peak_job',SIZE)]


class Container:
    def __init__(self,name):
        self.name=name;self.sid=P()
        hr=create_profile(name,name,'Disposable Guardian conformance laboratory',None,0,c.byref(self.sid))
        if hr < 0:raise OSError(f'CreateAppContainerProfile HRESULT {hr & 0xffffffff:08x}')
        self.principal=sid_string(self.sid)

    def launch(self, argv, cwd, timeout=30):
        init=api(k,'InitializeProcThreadAttributeList',w.BOOL,P,w.DWORD,w.DWORD,c.POINTER(SIZE))
        update=api(k,'UpdateProcThreadAttribute',w.BOOL,P,w.DWORD,SIZE,P,SIZE,P,P)
        destroy=api(k,'DeleteProcThreadAttributeList',None,P)
        create=api(k,'CreateProcessW',w.BOOL,w.LPCWSTR,w.LPWSTR,P,P,w.BOOL,w.DWORD,P,w.LPCWSTR,c.POINTER(STARTUPINFOEX),c.POINTER(PROCESSINFO))
        resume=api(k,'ResumeThread',w.DWORD,w.HANDLE)
        wait=api(k,'WaitForSingleObject',w.DWORD,w.HANDLE,w.DWORD)
        terminate=api(k,'TerminateProcess',w.BOOL,w.HANDLE,w.UINT)
        exitcode=api(k,'GetExitCodeProcess',w.BOOL,w.HANDLE,c.POINTER(w.DWORD))
        size=SIZE();init(None,1,0,c.byref(size));buf=c.create_string_buffer(size.value)
        check(init(buf,1,0,c.byref(size)));caps=CAPABILITIES(self.sid,None,0,0)
        check(update(buf,0,0x20009,c.byref(caps),c.sizeof(caps),None,None))
        si=STARTUPINFOEX();si.StartupInfo.cb=c.sizeof(si);si.lpAttributeList=c.cast(buf,P)
        pi=PROCESSINFO();command=c.create_unicode_buffer(subprocess.list2cmdline([str(x) for x in argv]))
        names=['SystemRoot','WINDIR','SystemDrive','USERPROFILE','LOCALAPPDATA','APPDATA','ProgramFiles','ProgramData','COMSPEC']
        values={name:os.environ[name] for name in names if name in os.environ}
        values.update(PATH=os.path.join(os.environ['SystemRoot'],'System32'),PYTHONHASHSEED='0',TEMP=str(cwd),TMP=str(cwd))
        env=c.create_unicode_buffer('\0'.join(key+'='+values[key] for key in sorted(values,key=str.upper))+'\0\0')
        job=None
        try:
            job=api(k,'CreateJobObjectW',w.HANDLE,P,w.LPCWSTR)(None,None);check(job)
            limits=EXTENDED_LIMIT();limits.basic.flags=0x2000|8;limits.basic.active_processes=1
            check(api(k,'SetInformationJobObject',w.BOOL,w.HANDLE,c.c_int,P,w.DWORD)(job,9,c.byref(limits),c.sizeof(limits)))
            check(create(str(argv[0]),command,None,None,False,0x80000|4|0x08000000|0x400,env,str(cwd),c.byref(si),c.byref(pi)))
            try:
                if not api(k,'AssignProcessToJobObject',w.BOOL,w.HANDLE,w.HANDLE)(job,pi.hProcess):
                    terminate(pi.hProcess,97);raise c.WinError(c.get_last_error())
                token=token_info(pi.hProcess)
                if not token['appcontainer'] or token['appcontainer_sid'] != self.principal or token['elevated']:
                    diagnostic={key:value for key,value in token.items() if key!='user_sid'}
                    terminate(pi.hProcess,99);raise RuntimeError('agent token isolation not established: '+str(diagnostic))
                if resume(pi.hThread)==0xffffffff:raise c.WinError(c.get_last_error())
                if wait(pi.hProcess,timeout*1000)!=0:
                    terminate(pi.hProcess,98);raise TimeoutError('agent process timeout')
                code=w.DWORD();check(exitcode(pi.hProcess,c.byref(code)))
                return {'exit_code':code.value,'token':token,'pid':pi.dwProcessId,'argv':[str(x) for x in argv]}
            finally:close(pi.hThread);close(pi.hProcess)
        finally:
            if job:close(job)
            destroy(buf)

    def close(self):
        if self.sid:
            free_sid(self.sid);self.sid=None
            hr=delete_profile(self.name)
            if hr < 0:raise OSError(f'DeleteAppContainerProfile HRESULT {hr & 0xffffffff:08x}')
