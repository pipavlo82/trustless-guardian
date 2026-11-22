"""An independent child tries changing the protected object's DACL directly."""
import argparse
from pathlib import Path
from lab import Lab,write
from guardian.policy import digest

PROBE=r'''import ctypes as c
from ctypes import wintypes as w
import json,sys
from pathlib import Path
config=json.loads(Path(sys.argv[1]).read_bytes());out=Path(config['out'])
(out/'scratch').write_bytes(b'positive')
a=c.WinDLL('advapi32',use_last_error=True);k=c.WinDLL('kernel32',use_last_error=True)
a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,c.POINTER(c.c_void_p),c.c_void_p]
a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=w.BOOL
a.SetFileSecurityW.argtypes=[w.LPCWSTR,w.DWORD,c.c_void_p];a.SetFileSecurityW.restype=w.BOOL
k.LocalFree.argtypes=[c.c_void_p];k.LocalFree.restype=c.c_void_p
sd=c.c_void_p()
if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW('D:(A;;FA;;;WD)',1,c.byref(sd),None):raise c.WinError(c.get_last_error())
ok=a.SetFileSecurityW(config['resource'],4,sd);error=c.get_last_error();k.LocalFree(sd)
(out/'worker.json').write_text(json.dumps({'completed':True,'acl_changed':bool(ok),'winerror':error}))
'''


def run(out):
    lab=Lab(out)
    try:
        before=lab.resource.read_bytes();(lab.runtime/'agent_worker.py').write_bytes(PROBE.encode('ascii'))
        inbox,worker,process=lab.agent('ownership','single_write')
        after=lab.resource.read_bytes()
        passed=(not worker['acl_changed'] and worker['winerror']==5 and before==after and (inbox/'scratch').read_bytes()==b'positive')
        report={'passed':passed,'worker':worker,'before_sha256':digest(before),'after_sha256':digest(after),
          'process_exit':process['exit_code'],'probe_sha256':digest(PROBE.encode('ascii')),
          'meaning':'AppContainer cannot grant itself write permission through this DACL API in the tested context'}
        write(out/'report.json',report);print(report);return passed
    finally:lab.close()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();raise SystemExit(not run(a.out.absolute()))
