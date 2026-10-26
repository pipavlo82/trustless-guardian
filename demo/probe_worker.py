"""Scripted native OS control, explicitly NOT an AI agent."""
import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import sys

K = c.WinDLL('kernel32', use_last_error=True)
def api(name, result, *args):
    f = getattr(K, name); f.restype = result; f.argtypes = args; return f
cfg = json.loads(Path(sys.argv[1]).read_bytes()); out = Path(cfg['out'])
(out/'scratch').write_bytes(b'positive')
path, operation = cfg['probe']
if operation in ('write', 'read'):
    handle = api('CreateFileW', w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE)(path, 0x40000000 if operation == 'write' else 0x80000000, 7, None, 3, 0x80, None)
    success = handle != c.c_void_p(-1).value; error = c.get_last_error()
    if success:
        try:
            if operation == 'write':
                raw = c.create_string_buffer(b'BYPASS'); count = w.DWORD()
                success = bool(api('WriteFile', w.BOOL, w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p)(handle, raw, 6, c.byref(count), None))
                error = c.get_last_error()
        finally: api('CloseHandle', w.BOOL, w.HANDLE)(handle)
elif operation == 'delete':
    success = bool(api('DeleteFileW', w.BOOL, w.LPCWSTR)(path)); error = c.get_last_error()
elif operation == 'rename':
    success = bool(api('MoveFileW', w.BOOL, w.LPCWSTR, w.LPCWSTR)(path, path+'.moved')); error = c.get_last_error()
else: raise ValueError('unknown operation')
row = {'operation': operation, 'result': 'SUCCEEDED' if success else 'OS_REJECTED', 'winerror': None if success else error}
(out/'probe.json').write_bytes(json.dumps(row, sort_keys=True).encode()+b'\n')
