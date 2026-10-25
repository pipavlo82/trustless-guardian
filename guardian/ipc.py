"""Local message pipe v02. Identification token only; no client impersonated I/O."""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import time
from . import windows as win
from .policy import parse, canonical
from .protocol import LIMIT, envelope

CLIENT_ACCESS = 0x12019b  # no FILE_CREATE_PIPE_INSTANCE (0x4)


class OVERLAPPED(c.Structure):
    _fields_ = [('Internal',win.SIZE),('InternalHigh',win.SIZE),('Offset',w.DWORD),
                ('OffsetHigh',w.DWORD),('hEvent',w.HANDLE)]


class SA(c.Structure):
    _fields_ = [('length',w.DWORD),('descriptor',win.P),('inherit',w.BOOL)]


def token_details(token):
    def query(kind):
        size=w.DWORD();win.get_token(token,kind,None,0,c.byref(size))
        data=c.create_string_buffer(size.value)
        win.check(win.get_token(token,kind,data,size,c.byref(size)));return data
    user=query(1);app=query(31);integrity=query(25)
    sid=c.cast(app,c.POINTER(win.P))[0]
    return {'user_sha256':hashlib.sha256(win.sid_string(c.cast(user,c.POINTER(win.P))[0]).encode()).hexdigest(),
      'appcontainer_sid':win.sid_string(sid) if sid else None,
      'appcontainer':bool(c.cast(query(29),c.POINTER(w.DWORD))[0]),
      'elevated':bool(c.cast(query(20),c.POINTER(w.DWORD))[0]),
      'integrity_sid':win.sid_string(c.cast(integrity,c.POINTER(win.P))[0]),
      'capability_count':int(c.cast(query(30),c.POINTER(w.DWORD))[0])}


def authenticate(pipe, expected_sid, expected_user):
    win.check(win.api(win.a,'ImpersonateNamedPipeClient',w.BOOL,w.HANDLE)(pipe))
    token=w.HANDLE()
    try:
        win.check(win.api(win.a,'OpenThreadToken',w.BOOL,w.HANDLE,w.DWORD,w.BOOL,c.POINTER(w.HANDLE))(
            win.api(win.k,'GetCurrentThread',w.HANDLE)(),8,True,c.byref(token)))
        observed=token_details(token)
    finally:
        if token: win.close(token)
        # Failure must terminate the serving process, never execute under the client.
        if not win.api(win.a,'RevertToSelf',w.BOOL)():
            win.api(win.k,'TerminateProcess',w.BOOL,w.HANDLE,w.UINT)(win.current(),91)
            raise RuntimeError('REVERT_FAILED')
    if (not observed['appcontainer'] or observed['elevated'] or observed['capability_count'] != 0
        or observed['integrity_sid'] != 'S-1-16-4096' or observed['user_sha256'] != expected_user
        or observed['appcontainer_sid'] != expected_sid):  # V02 caller_identity
        raise PermissionError('IPC_CALLER')
    return observed


def io(handle, operation, data=None, timeout_ms=3000):
    """Overlapped operation; cancel and drain before freeing OVERLAPPED/buffer."""
    event=win.api(win.k,'CreateEventW',w.HANDLE,win.P,w.BOOL,w.BOOL,w.LPCWSTR)(None,True,False,None)
    win.check(event);ov=OVERLAPPED();ov.hEvent=event;count=w.DWORD()
    buf=c.create_string_buffer(LIMIT+1) if operation=='read' else c.create_string_buffer(data or b'')
    try:
        if operation=='connect':
            ok=win.api(win.k,'ConnectNamedPipe',w.BOOL,w.HANDLE,c.POINTER(OVERLAPPED))(handle,c.byref(ov))
        else:
            fn=win.api(win.k,'ReadFile' if operation=='read' else 'WriteFile',w.BOOL,w.HANDLE,win.P,w.DWORD,c.POINTER(w.DWORD),c.POINTER(OVERLAPPED))
            ok=fn(handle,buf,LIMIT+1 if operation=='read' else len(data),c.byref(count),c.byref(ov))
        error=c.get_last_error()
        if not ok and operation=='connect' and error==535: return b''
        if not ok and error!=997: raise c.WinError(error)
        result=win.api(win.k,'GetOverlappedResult',w.BOOL,w.HANDLE,c.POINTER(OVERLAPPED),c.POINTER(w.DWORD),w.BOOL)
        if not ok:
            waited=win.api(win.k,'WaitForSingleObject',w.DWORD,w.HANDLE,w.DWORD)(event,timeout_ms)
            if waited!=0:
                win.api(win.k,'CancelIoEx',w.BOOL,w.HANDLE,c.POINTER(OVERLAPPED))(handle,c.byref(ov))
                result(handle,c.byref(ov),c.byref(count),True)
                raise TimeoutError('IPC_TIMEOUT_CANCELLED')
        win.check(result(handle,c.byref(ov),c.byref(count),False))
        if operation=='read':
            if count.value>LIMIT: raise ValueError('SIZE')
            return buf.raw[:count.value]
        if operation=='write' and count.value!=len(data): raise OSError('IPC_SHORT_WRITE')
        return b''
    finally: win.close(event)


class Server:
    def __init__(self, name, broker_sid, client_sid, host_sid):
        # Full control only for broker/host. Client cannot create another server instance.
        sddl=f'D:P(A;;FA;;;{host_sid})(A;;FA;;;{broker_sid})(A;;0x12019b;;;{client_sid})S:(ML;;NW;;;LW)'
        sd=win.P();win.check(win.api(win.a,'ConvertStringSecurityDescriptorToSecurityDescriptorW',w.BOOL,w.LPCWSTR,w.DWORD,c.POINTER(win.P),win.P)(sddl,1,c.byref(sd),None))
        try:
            sa=SA(c.sizeof(SA),sd,False)
            self.handle=win.api(win.k,'CreateNamedPipeW',w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,c.POINTER(SA))(
                name,3|0x40000000|0x80000,4|2|8,1,LIMIT,LIMIT,3000,c.byref(sa))
            if self.handle==c.c_void_p(-1).value:raise c.WinError(c.get_last_error())
        finally:win.local_free(sd)
    def close(self):
        if self.handle:win.close(self.handle);self.handle=None


def connect(name, expected_server_pid):
    until=time.monotonic()+3
    while True:
        h=win.api(win.k,'CreateFileW',w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,win.P,w.DWORD,w.DWORD,w.HANDLE)(
            name,CLIENT_ACCESS,0,None,3,0x40000000|0x100000|0x10000,None)  # identification SQOS
        if h!=c.c_void_p(-1).value:break
        error=c.get_last_error()
        if error!=231 or time.monotonic()>=until:raise c.WinError(error)
        time.sleep(.01)
    try:
        pid=w.ULONG();win.check(win.api(win.k,'GetNamedPipeServerProcessId',w.BOOL,w.HANDLE,c.POINTER(w.ULONG))(h,c.byref(pid)))
        if pid.value!=expected_server_pid:raise PermissionError('IPC_SERVER')  # V02 server_identity
        mode=w.DWORD(2)
        win.check(win.api(win.k,'SetNamedPipeHandleState',w.BOOL,w.HANDLE,c.POINTER(w.DWORD),win.P,win.P)(h,c.byref(mode),None,None))
        return h
    except Exception:win.close(h);raise


def exchange(name, expected_server_pid, raw):
    h=connect(name,expected_server_pid)
    try:
        io(h,'write',raw);response=io(h,'read')
        # ACK only avoids server disconnect discarding unread response; not authorization.
        io(h,'write',b'ACK');return parse(response)
    finally:win.close(h)
