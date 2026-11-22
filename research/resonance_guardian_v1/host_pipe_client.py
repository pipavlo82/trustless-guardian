"""Negative control: ordinary host user attempts to claim AppContainer broker channel."""
import ctypes as c
from ctypes import wintypes as w
import json
import os
import sys
k=c.WinDLL("kernel32",use_last_error=True)
def api(n,r,*t):
    x=getattr(k,n);x.restype=r;x.argtypes=list(t);return x
open_pipe=api("CreateFileW",w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE)
read=api("ReadFile",w.BOOL,w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p)
write=api("WriteFile",w.BOOL,w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p)
close=api("CloseHandle",w.BOOL,w.HANDLE)
if len(sys.argv)!=2:sys.exit(72)
h=open_pipe(os.path.join(r"\\.\pipe",sys.argv[1]),0xc0000000,0,None,3,0,None)
if h==c.c_void_p(-1).value:sys.exit(100)
try:
    raw=json.dumps({"schema":"resonance.ipc-client.v0","op":"HELLO","agent_id":"resonance-agent-v5"}).encode()
    b=c.create_string_buffer(raw);n=w.DWORD()
    if not write(h,b,len(raw),c.byref(n),None):sys.exit(101)
    buf=c.create_string_buffer(4096)
    if not read(h,buf,4096,c.byref(n),None):sys.exit(102)
    response=json.loads(buf.raw[:n.value])
    print(json.dumps(response,sort_keys=True))
    sys.exit(74 if response.get("verdict")=="DENY_CLIENT_IDENTITY" else 103)
finally:
    close(h)
