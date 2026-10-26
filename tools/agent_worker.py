"""Untrusted-side witness process. Results are cross-checked by the host harness."""
import ctypes
import json
import os
from pathlib import Path
import sys

config=json.loads(Path(sys.argv[1]).read_bytes())
out=Path(config['out']);target=Path(config['resource']);rows=[]
def attempt(name,fn):
    try:fn();rows.append({'name':name,'result':'SUCCEEDED'})
    except OSError as e:rows.append({'name':name,'result':'OS_REJECTED','errno':e.errno,'winerror':e.winerror,'type':type(e).__name__})

if config['mode']=='request':
    (out/'request.json').write_text(json.dumps(config['request']),encoding='utf-8')
    rows.append({'name':'submit_request','result':'SUCCEEDED'})
elif config['mode']=='single_write':
    attempt('scratch_positive',lambda:(out/'scratch.txt').write_bytes(b'positive control'))
    attempt('direct_write',lambda:target.write_bytes(b'bypass'))
else:
    attempt('scratch_positive',lambda:(out/'scratch.txt').write_bytes(b'agent can execute and write scratch'))
    attempt('direct_write',lambda:target.write_bytes(b'bypass'))
    attempt('direct_delete',lambda:target.unlink())
    attempt('direct_rename',lambda:target.rename(out/'stolen.txt'))
    attempt('extended_path_write',lambda:Path('\\\\?\\'+str(target)).write_bytes(b'alternate'))
    attempt('junction_write',lambda:(out/'junction/resource.txt').write_bytes(b'junction'))
    attempt('policy_write',lambda:Path(config['policy']).write_bytes(b'{}'))
    attempt('parent_rename',lambda:target.parent.rename(out/'stolen-directory'))
    attempt('hardlink_create',lambda:os.link(target,out/'hardlink.txt'))
    if (out/'hardlink.txt').exists():attempt('hardlink_write',lambda:(out/'hardlink.txt').write_bytes(b'hardlink'))
    # Broker code is not required for the attack: native file access remains denied.
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_void_p]
    kernel.CreateFileW.restype=ctypes.c_void_p
    handle=kernel.CreateFileW(str(target),0x40000000,0,None,3,0,None)
    if handle==ctypes.c_void_p(-1).value:rows.append({'name':'native_write_handle','result':'OS_REJECTED','winerror':ctypes.get_last_error()})
    else:
        kernel.CloseHandle.argtypes=[ctypes.c_void_p];kernel.CloseHandle(handle)
        rows.append({'name':'native_write_handle','result':'SUCCEEDED'})
(out/'worker.json').write_text(json.dumps({'completed':True,'rows':rows}),encoding='utf-8')
