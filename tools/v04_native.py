"""Independent read-only Win32 observer. No Guardian imports or policy oracle."""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import os

if os.name!='nt':raise ImportError('Windows witness unavailable')
K=c.WinDLL('kernel32',use_last_error=True);A=c.WinDLL('advapi32',use_last_error=True)
P=c.c_void_p
def api(dll,name,result,*args):
    f=getattr(dll,name);f.restype=result;f.argtypes=list(args);return f
def check(v):
    if not v:raise c.WinError(c.get_last_error())
close=api(K,'CloseHandle',w.BOOL,w.HANDLE)
def token_query(token,kind):
    f=api(A,'GetTokenInformation',w.BOOL,w.HANDLE,c.c_int,P,w.DWORD,c.POINTER(w.DWORD))
    size=w.DWORD();f(token,kind,None,0,c.byref(size));buf=c.create_string_buffer(size.value)
    check(f(token,kind,buf,len(buf),c.byref(size)));return buf
def sid(pointer):
    out=w.LPWSTR();check(api(A,'ConvertSidToStringSidW',w.BOOL,P,c.POINTER(w.LPWSTR))(pointer,c.byref(out)))
    try:return out.value
    finally:api(K,'LocalFree',P,P)(out)
def describe(token):
    scalar=lambda k:int(c.cast(token_query(token,k),c.POINTER(w.DWORD))[0])
    # Keep token buffers alive until each SID conversion finishes.
    def sid_at(k):
        buf=token_query(token,k);value=c.cast(buf,c.POINTER(P))[0];return sid(value) if value else None
    kind=scalar(8)
    return {'token_type':kind,'level':scalar(9) if kind==2 else None,
        'user_sha256':hashlib.sha256(sid_at(1).encode()).hexdigest(),
        'appcontainer_sid':sid_at(31),'appcontainer':bool(scalar(29)),
        'integrity_sid':sid_at(25),'elevated':bool(scalar(20)),
        'capability_count':scalar(30),'session_id':scalar(12)}
def thread():
    token=w.HANDLE()
    ok=api(A,'OpenThreadToken',w.BOOL,w.HANDLE,w.DWORD,w.BOOL,c.POINTER(w.HANDLE))(
        api(K,'GetCurrentThread',w.HANDLE)(),8,True,c.byref(token))
    if not ok:return {'present':False,'winerror':c.get_last_error()}
    try:return {'present':True,**describe(token)}
    finally:close(token)
def process(pid=None):
    handle=api(K,'OpenProcess',w.HANDLE,w.DWORD,w.BOOL,w.DWORD)(0x1000,False,pid) if pid else api(K,'GetCurrentProcess',w.HANDLE)()
    check(handle);token=w.HANDLE()
    try:
        check(api(A,'OpenProcessToken',w.BOOL,w.HANDLE,w.DWORD,c.POINTER(w.HANDLE))(handle,8,c.byref(token)))
        return describe(token)
    finally:
        if token:close(token)
        if pid:close(handle)
