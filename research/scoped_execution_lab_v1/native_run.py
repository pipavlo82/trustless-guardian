"""Native Windows zero-capability agent -> authenticated broker -> lab worker.

Private test keys pass only over inherited anonymous stdin; never to AppContainer.
"""
import argparse
import ctypes as c
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from guardian.windows import Container,acl,low_label
from research.guardian_mutual_ipc_v1.native import package
from research.guardian_mutual_ipc_v1.protocol import encode,ClientSession
from research.resonance_guardian_v1 import broker_host as win
from research.guardian_mutual_ipc_v1.broker import send,receive

def run(out,case):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    root=Path(tempfile.mkdtemp(prefix='guardian-lab-scoped-native-'));container=None;proc=None
    result={'case':case,'scope':'NATIVE_WINDOWS_LAB_ONLY','started_at':int(time.time())}
    try:
        key=Ed25519PrivateKey.generate();now=int(time.time())
        trust={'schema':'guardian.broker-trust.v1','broker_id':'guardian-lab','trust_root_version':'lab-root-v1','key_id':'lab-ed25519',
               'public_key':key.public_key().public_bytes_raw().hex(),'revoked':False,'not_before':now-5,'expires_at':now+1800}
        rt=package(root,trust);diag=root/'client-io.json';diag.write_bytes(b'')
        protected=out/'protected-state-sentinel.txt';protected.write_bytes(b'PUBLIC_SYNTHETIC_PROTECTED_SENTINEL\n')
        probe=rt/'probe.py'
        probe.write_bytes(b"import sys,json,ctypes as c\nfrom ctypes import wintypes as w\nfrom pathlib import Path\nk=c.WinDLL('kernel32',use_last_error=True)\nf=k.CreateFileW;f.restype=w.HANDLE;f.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE]\nk.CloseHandle.argtypes=[w.HANDLE]\nr={}\nfor mode,access in [('rb',0x80000000),('wb',0x40000000)]:\n h=f(sys.argv[1],access,0,None,3,0,None)\n if h==c.c_void_p(-1).value:r[mode]=c.get_last_error()\n else:r[mode]='UNEXPECTED_ACCESS';k.CloseHandle(h)\nPath(sys.argv[2]).write_text(json.dumps(r))\nraise SystemExit(0 if r=={'rb':5,'wb':5} else 1)\n")
        container=Container('guardian-scoped-'+uuid.uuid4().hex[:12]);sid=container.principal
        for path in [root,rt,*rt.rglob('*')]:acl(root,path,sid,writable=False)
        acl(root,diag,sid,writable=True);low_label(root,root)
        probe_result=container.launch([str(rt/'python.exe'),'-I','-B',str(probe),str(protected),str(diag)],root,timeout=15)
        result['protected_probe']={'process':probe_result,'access':json.loads(diag.read_bytes()),'unchanged':protected.read_bytes()==b'PUBLIC_SYNTHETIC_PROTECTED_SENTINEL\n'}
        if probe_result['exit_code']!=0 or not result['protected_probe']['unchanged']:raise RuntimeError('PROTECTED_RESOURCE_BOUNDARY_FAILED')
        diag.write_bytes(b'')
        (out/'trust.json').write_bytes(encode(trust))
        channel='guardian-resonance-'+secrets.token_hex(12)
        args=[sys.executable,'-B',str(Path(__file__).with_name('native_server.py')),'--channel',channel,'--sid',sid,
              '--ready',str(out/'ready'),'--out',str(out),'--trust',str(out/'trust.json'),'--mode',case]
        proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        proc.stdin.write(encode({'key':key.private_bytes_raw().hex()})+b'\n');proc.stdin.close();proc.stdin=None
        for _ in range(200):
            if (out/'ready').exists() or proc.poll() is not None:break
            time.sleep(.05)
        if not (out/'ready').exists():raise RuntimeError('BROKER_NOT_READY')
        result.update(broker_pid=proc.pid,appcontainer_sid=sid,channel_id=channel)
        if case=='host_spoof':
            opener=win.api(win.k,'CreateFileW',win.w.HANDLE,win.w.LPCWSTR,win.w.DWORD,win.w.DWORD,win.P,win.w.DWORD,win.w.DWORD,win.w.HANDLE)
            h=opener(os.path.join(r'\\.\pipe',channel),0xc0000000,0,None,3,0,None);win.check(h!=win.INVALID,'HOST_CONNECT')
            try:send(h,ClientSession(trust,channel,int(time.time())).hello);result['host_reply']=receive(h)
            finally:win.close(h)
        else:
            observed=container.launch([str(rt/'python.exe'),'-I','-B',str(rt/'client.py'),channel,case if case in ('bad_nonce','bad_tool') else 'normal',str(diag)],root,timeout=20)
            result['client']=observed;result['client_io']=json.loads(diag.read_bytes())
        so,se=proc.communicate(timeout=45)
        (out/'broker.stdout').write_bytes(so);(out/'broker.stderr').write_bytes(se)
        result['broker_exit']=proc.returncode
        result['execution']=json.loads((out/'execution.json').read_bytes())
        result['status']='OBSERVED'
    except Exception as error:
        result.update(status='CONTROL_BROKEN',error=type(error).__name__,reason=str(error))
    finally:
        if proc and proc.poll() is None:proc.kill();proc.communicate(timeout=5)
        if container:container.close()
        shutil.rmtree(root,ignore_errors=True)
        result['temporary_root_deleted']=not root.exists();result['finished_at']=int(time.time())
        (out/'native.json').write_bytes(encode(result)+b'\n')
    print(json.dumps(result,sort_keys=True));return 0 if result['status']=='OBSERVED' else 2

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--case',choices=['normal','host_spoof','bad_nonce','bad_tool','revoked_policy'],default='normal');a=p.parse_args();raise SystemExit(run(a.out,a.case))
