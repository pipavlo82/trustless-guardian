"""A real inheritable write handle in the host must not reach the agent child."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import sys
import shutil

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.v02_lab import Lab02,write
from guardian.broker import LockedFile
from guardian import windows as win
from guardian.policy import digest

PROBE=r'''
import ctypes as c,json,sys
from ctypes import wintypes as w
from pathlib import Path
cfg=json.loads(Path(sys.argv[1]).read_bytes());out=Path(cfg['out'])
(out/'scratch').write_bytes(b'positive')
k=c.WinDLL('kernel32',use_last_error=True);f=k.WriteFile
f.argtypes=[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p];f.restype=w.BOOL
n=w.DWORD();payload=b'unauthorized-handle-write'
try:ok=f(cfg['handle'],payload,len(payload),c.byref(n),None);error=c.get_last_error()
except OSError as exc:ok=False;error=exc.winerror
(out/'result.json').write_bytes(json.dumps({'completed':True,'write_succeeded':bool(ok),'winerror':error,'written':n.value}).encode())
'''


def run(out):
    lab=Lab02(out)
    try:
        script=lab.runtime/'handle_probe.py';script.write_bytes(PROBE.encode());lab.acl(script)
        scratch=lab.root/'handle-scratch';scratch.mkdir();lab.acl(scratch,broker=None,agent='FA',other=None);win.low_label(lab.root,scratch)
        with LockedFile(lab.resource,True) as resource:
            resource.replace(b'approved:handle-positive');before=resource.read()
            win.check(win.api(win.k,'SetHandleInformation',w.BOOL,w.HANDLE,w.DWORD,w.DWORD)(resource.handle,1,1))
            cfg=lab.runtime/'handle-config.json';write(cfg,{'out':str(scratch),'handle':resource.handle});lab.acl(cfg)
            snippet=('import sys,runpy;sys.stderr=open('+repr(str(scratch/'stderr.log'))+",'w');"
                     +'sys.argv='+repr([str(script),str(cfg)])+';runpy.run_path('+repr(str(script))+",run_name='__main__')")
            child=lab.agent.launch([lab.runtime/'python.exe','-B','-c',snippet],lab.runtime)
            child['token']['user_sid_sha256']=digest(child['token'].pop('user_sid').encode())
            write(out/'child.json',child)
            if (scratch/'stderr.log').exists():shutil.copyfile(scratch/'stderr.log',out/'child.stderr')
            after_handle=resource.read()
        actual=lab.resource.read_bytes();observed=json.loads((scratch/'result.json').read_bytes())
        passed=(child['exit_code']==0 and (scratch/'scratch').read_bytes()==b'positive'
                and not observed['write_succeeded'] and observed['winerror'] in (6,-1073741816) and actual==after_handle==before)
        result={'passed':passed,'observation':observed,'before_sha256':digest(before),'after_sha256':digest(actual),
                'positive_control':'host wrote through the same real inheritable handle before spawning child',
                'probe_sha256':digest(PROBE.encode()),'scope':'one real privileged host handle; no universal handle audit'}
        write(out/'report.json',result);print(json.dumps(result));return result
    finally:lab.close()


if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--out',type=Path,required=True);v=a.parse_args();raise SystemExit(not run(v.out.absolute())['passed'])
