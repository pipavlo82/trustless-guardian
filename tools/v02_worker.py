"""Disposable child entry point. Configuration is provisioned read-only by the host."""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import sys
import time
from guardian import windows as win
from guardian import ipc
from guardian.hardened import HardenedBroker, refusal
from guardian.policy import canonical, digest


def save(path,value):path.write_bytes(json.dumps(value,sort_keys=True,indent=2).encode()+b'\n')


def server(cfg):
    root=Path(cfg['root']);out=root/'journal';rows=[]
    broker=HardenedBroker(cfg)
    pipe=ipc.Server(cfg['pipe_local'],cfg['broker_sid'],cfg.get('fixture_pipe_sid',cfg['agent_sid']),win.token_info()['user_sid'])
    save(out/'ready.json',{'pid':os.getpid()})
    def fault(stage,resource,raw):
        selected=cfg.get('fixture_crash')
        if selected=='PARTIAL' and stage=='PREPARED':
            resource.replace(raw[:max(1,len(raw)//2)]);os._exit(73)
        if selected==stage:os._exit(73)
        if cfg.get('fixture_pause')==stage:
            save(out/'paused.json',{'stage':stage})
            until=time.monotonic()+5
            while not (out/'continue').exists() and time.monotonic()<until:time.sleep(.01)
            if not (out/'continue').exists():raise TimeoutError('TEST_BARRIER_TIMEOUT')
    try:
        for _ in range(cfg.get('connections',1)):
            connected=False
            try:
                ipc.io(pipe.handle,'connect',timeout_ms=cfg.get('timeout_ms',1800));connected=True
                raw=ipc.io(pipe.handle,'read',timeout_ms=cfg.get('timeout_ms',1800))
                identity=ipc.authenticate(pipe.handle,cfg['agent_sid'],cfg['user_sha256'])
                response=broker.execute(raw,identity['appcontainer_sid'],cfg.get('fixture_time',int(time.time())),fault)
                row={'response':response,'identity':identity,'request_sha256':digest(raw)}
            except Exception as exc:
                response=refusal(type(exc).__name__+': '+str(exc),'UNVERIFIABLE' if isinstance(exc,(OSError,TimeoutError)) else 'REFUTED')
                row={'response':response,'transport_error':True}
            rows.append(row);save(out/'server.json',rows)
            if connected:
                try:
                    ipc.io(pipe.handle,'write',canonical(response),timeout_ms=700)
                    ipc.io(pipe.handle,'read',timeout_ms=700)
                except (OSError,TimeoutError,ValueError):pass
                win.check(win.api(win.k,'DisconnectNamedPipe',w.BOOL,w.HANDLE)(pipe.handle))
    finally:pipe.close();broker.close()


def client(cfg):
    out=Path(cfg['out']);(out/'scratch').write_bytes(b'positive')
    result={'completed':True}
    try:
        if cfg.get('fixture_idle'):
            h=ipc.connect(cfg['pipe'],cfg['server_pid'])
            try:time.sleep(2.3)
            finally:win.close(h)
            result['idle_completed']=True
        else:
            result['response']=ipc.exchange(cfg['pipe'],cfg['server_pid'],bytes.fromhex(cfg['raw_hex']))
    except Exception as exc:
        result.update(error=type(exc).__name__+': '+str(exc),winerror=getattr(exc,'winerror',None))
    save(out/'client.json',result)


def probe(cfg):
    """A confined child tries direct access, independently observed by the host."""
    out=Path(cfg['out']);(out/'scratch').write_bytes(b'positive');rows=[]
    for path,operation in cfg['probes']:
        try:
            if operation=='read':Path(path).read_bytes()
            elif operation=='write':Path(path).write_bytes(b'probe-write')
            elif operation=='delete':Path(path).unlink()
            elif operation=='rename':Path(path).rename(str(path)+'.moved')
            elif operation=='hardlink':os.link(path,out/'hardlink.txt')
            elif operation=='acl':
                sd=win.P();win.check(win.api(win.a,'ConvertStringSecurityDescriptorToSecurityDescriptorW',w.BOOL,w.LPCWSTR,w.DWORD,c.POINTER(win.P),win.P)('D:(A;;FA;;;WD)',1,c.byref(sd),None))
                try:win.check(win.api(win.a,'SetFileSecurityW',w.BOOL,w.LPCWSTR,w.DWORD,win.P)(path,4,sd))
                finally:win.local_free(sd)
            rows.append({'operation':operation,'target':Path(path).name,'result':'SUCCEEDED'})
        except OSError as exc:rows.append({'operation':operation,'target':Path(path).name,'result':'OS_REJECTED','winerror':exc.winerror})
    save(out/'probe.json',{'rows':rows,'completed':True})


if __name__=='__main__':
    cfg=json.loads(Path(sys.argv[1]).read_bytes())
    try:{'server':server,'client':client,'probe':probe}[cfg['role']](cfg)
    except Exception as exc:
        save(Path(cfg['root'])/'journal/fatal.json',{'error':type(exc).__name__+': '+str(exc)})
        raise
