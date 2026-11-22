"""Local overlapped named-pipe I/O, bounded cancellation, no runtime ACL expansion.

The caller owns a single pipe handle. Buffers/OVERLAPPED remain alive until completion.
If Windows cannot confirm cancellation within the grace period, the process exits;
it must never free an OVERLAPPED still owned by the kernel. Not an auth decision.
"""
import ctypes as c
from ctypes import wintypes as w
import os
import time

k = c.WinDLL('kernel32', use_last_error=True)
def api(name, result, *args):
    f = getattr(k, name); f.restype = result; f.argtypes = list(args); return f

class OVERLAPPED(c.Structure):
    _fields_ = [('Internal', c.c_size_t), ('InternalHigh', c.c_size_t),
                ('Offset', w.DWORD), ('OffsetHigh', w.DWORD), ('hEvent', w.HANDLE)]

CreateFile = api('CreateFileW', w.HANDLE, w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE)
CreateEvent = api('CreateEventW',w.HANDLE,c.c_void_p,w.BOOL,w.BOOL,w.LPCWSTR)
Wait = api('WaitForSingleObject',w.DWORD,w.HANDLE,w.DWORD)
Cancel = api('CancelIoEx',w.BOOL,w.HANDLE,c.POINTER(OVERLAPPED))
Result = api('GetOverlappedResult',w.BOOL,w.HANDLE,c.POINTER(OVERLAPPED),c.POINTER(w.DWORD),w.BOOL)
Read = api('ReadFile',w.BOOL,w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.POINTER(OVERLAPPED))
Write = api('WriteFile',w.BOOL,w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.POINTER(OVERLAPPED))
Close = api('CloseHandle',w.BOOL,w.HANDLE)
ServerPID = api('GetNamedPipeServerProcessId',w.BOOL,w.HANDLE,c.POINTER(w.ULONG))
Exit = api('ExitProcess',None,w.UINT)
IO_MS = 3000
CANCEL_MS = 1000
events = []

class Deadline(OSError): pass

def open_pipe(channel):
    h = CreateFile(os.path.join(r'\\.\pipe', channel),0xc0000000,0,None,3,0x40000000,None)
    if h == c.c_void_p(-1).value: raise OSError('IPC_CONNECT:'+str(c.get_last_error()))
    pid = w.ULONG()
    if not ServerPID(h,c.byref(pid)):
        Close(h); raise OSError('IPC_SERVER_PID')
    events.append({'op':'open','client_pid':os.getpid(),'broker_pid':pid.value,'identity_authority':False})
    return h

def transfer(handle, raw=None):
    started = time.monotonic()
    buf = c.create_string_buffer(raw) if raw is not None else c.create_string_buffer(8192)
    size = len(raw) if raw is not None else 8192
    ov = OVERLAPPED(); ov.hEvent = CreateEvent(None,True,False,None)
    if not ov.hEvent: raise OSError('IPC_EVENT')
    n = w.DWORD(); entry = {'op':'write' if raw is not None else 'read','budget_ms':IO_MS}
    try:
        ok = (Write if raw is not None else Read)(handle,buf,size,c.byref(n),c.byref(ov))
        err = 0 if ok else c.get_last_error()
        if not ok and err != 997: raise OSError('IPC_IO:'+str(err))
        if not ok:
            waited = Wait(ov.hEvent, IO_MS)
            if waited != 0:
                entry['cancel_requested'] = bool(Cancel(handle,c.byref(ov)))
                entry['cancel_error'] = 0 if entry['cancel_requested'] else c.get_last_error()
                entry['completion_wait'] = Wait(ov.hEvent, CANCEL_MS)
                if entry['completion_wait'] != 0:
                    # No return/unwind is safe while the kernel may still use this buffer.
                    Exit(90)
                completed = bool(Result(handle,c.byref(ov),c.byref(n),False))
                entry['completion_error'] = 0 if completed else c.get_last_error()
                entry['deadline_refused'] = True
                raise Deadline('IPC_DEADLINE')
        if not Result(handle,c.byref(ov),c.byref(n),False): raise OSError('IPC_RESULT:'+str(c.get_last_error()))
        if raw is not None and n.value != size: raise OSError('IPC_SHORT_WRITE')
        entry['bytes'] = n.value
        return buf.raw[:n.value]
    finally:
        entry['elapsed_ms'] = round((time.monotonic()-started)*1000)
        events.append(entry)
        Close(ov.hEvent)
