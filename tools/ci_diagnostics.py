"""Read-only runner diagnostics. This is not an enforcement test or a CI bypass."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guardian import windows as win
from tools.ci_tokens import inspect,reduced_token,acceptable


class OBJECT_BASIC(c.Structure):
    _fields_=[('attributes',w.ULONG),('granted_access',w.ULONG),('handle_count',w.ULONG),('pointer_count',w.ULONG),('reserved',w.ULONG*10)]


def access(handle):
    info=OBJECT_BASIC();length=w.ULONG()
    dll=c.WinDLL('ntdll',use_last_error=True)
    status=win.api(dll,'NtQueryObject',w.LONG,w.HANDLE,w.ULONG,win.P,w.ULONG,c.POINTER(w.ULONG))(handle,0,c.byref(info),c.sizeof(info),c.byref(length))
    return {'ntstatus':int(status),'granted_access':hex(info.granted_access) if status==0 else None}


def run(path):
    token=w.HANDLE();reduced=None;linked=w.HANDLE();thread=w.HANDLE()
    win.check(win.open_token(win.current(),0x8b,c.byref(token)))
    try:
        record={'schema':'guardian.ci-diagnostics.v03','platform':platform.platform(),'windows_version':list(sys.getwindowsversion()),'python':sys.version,'current_token':inspect(token),'current_token_handle':access(token)}
        job=w.BOOL();win.check(win.api(win.k,'IsProcessInJob',w.BOOL,w.HANDLE,w.HANDLE,c.POINTER(w.BOOL))(win.current(),None,c.byref(job)))
        record['in_job']=bool(job.value)
        ok=win.api(win.a,'OpenThreadToken',w.BOOL,w.HANDLE,w.DWORD,w.BOOL,c.POINTER(w.HANDLE))(win.api(win.k,'GetCurrentThread',w.HANDLE)(),8,True,c.byref(thread))
        record['thread_token']={'present':bool(ok),'winerror':0 if ok else c.get_last_error()}
        size=w.DWORD();ok=win.get_token(token,19,c.byref(linked),c.sizeof(linked),c.byref(size))
        record['linked_token']={'available':bool(ok),'winerror':0 if ok else c.get_last_error()}
        if ok:record['linked_token']['details']=inspect(linked)
        if record['current_token']['elevated']:
            reduced=reduced_token(token);record['reduced_token']=inspect(reduced);record['reduced_token_handle']=access(reduced)
            record['reduced_acceptable']=acceptable(record['reduced_token'],record['current_token']['user_sha256'])
        p=subprocess.run(['sc.exe','query','seclogon'],capture_output=True)
        record['secondary_logon_service']={'argv':['sc.exe','query','seclogon'],'exit_code':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')}
        enabled={n for n,v in record['current_token']['privilege_attributes'].items() if v['enabled']}
        record['create_process_as_user_candidate']={'required_already_enabled':['SeIncreaseQuotaPrivilege','SeAssignPrimaryTokenPrivilege'],
            'both_already_enabled':{'SeIncreaseQuotaPrivilege','SeAssignPrimaryTokenPrivilege'}<=enabled,
            'executed':False,'reason':'API may temporarily enable privileges; no fallback is executed without a demonstrated no-enable path'}
        record['enforcement']='NOT_COVERED';record['privileges_enabled_by_diagnostic']=False
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(json.dumps(record,sort_keys=True,indent=2).encode()+b'\n');return record
    finally:
        for h in (thread,linked,reduced,token):
            if h:win.close(h)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();print(json.dumps(run(a.out),sort_keys=True))
