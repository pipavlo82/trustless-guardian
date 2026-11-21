"""Barrier-enabled v02 client used only by the PR1 availability transition."""
import json
import os
from pathlib import Path
import sys
import time
import ctypes as c
from ctypes import wintypes as w

from v02_worker import probe, save
from guardian import ipc
from guardian import windows as win
from guardian.hardened import HardenedBroker, refusal
from guardian.policy import canonical, digest


def server(cfg):
    root = Path(cfg['root']); out = root/'journal'; rows = []
    broker = HardenedBroker(cfg)
    pipe = ipc.Server(cfg['pipe_local'], cfg['broker_sid'],
                      cfg.get('fixture_pipe_sid', cfg['agent_sid']), win.token_info()['user_sid'])
    save(out/'ready.json', {'pid': os.getpid()})
    timeout = int(cfg.get('timeout_ms', 15000))
    response_timeout = int(cfg.get('response_timeout_ms', 15000))
    try:
        connected = False
        try:
            ipc.io(pipe.handle, 'connect', timeout_ms=timeout); connected = True
            raw = ipc.io(pipe.handle, 'read', timeout_ms=timeout)
            identity = ipc.authenticate(pipe.handle, cfg['agent_sid'], cfg['user_sha256'])
            response = broker.execute(raw, identity['appcontainer_sid'], cfg.get('fixture_time', int(time.time())))
            row = {'response': response, 'identity': identity, 'request_sha256': digest(raw)}
        except Exception as exc:
            response = refusal(type(exc).__name__+': '+str(exc),
                               'UNVERIFIABLE' if isinstance(exc, (OSError, TimeoutError)) else 'REFUTED')
            row = {'response': response, 'transport_error': True}
        rows.append(row); save(out/'server.json', rows)
        if connected:
            try:
                ipc.io(pipe.handle, 'write', canonical(response), timeout_ms=response_timeout)
                ipc.io(pipe.handle, 'read', timeout_ms=response_timeout)
            except (OSError, TimeoutError, ValueError):
                pass
            win.check(win.api(win.k, 'DisconnectNamedPipe', w.BOOL, w.HANDLE)(pipe.handle))
    finally:
        pipe.close(); broker.close()


def client_exchange(cfg):
    timeout = int(cfg.get('client_timeout_ms', 15000))
    handle = ipc.connect(cfg['pipe'], cfg['server_pid'])
    try:
        ipc.io(handle, 'write', bytes.fromhex(cfg['raw_hex']), timeout_ms=timeout)
        response = ipc.io(handle, 'read', timeout_ms=timeout)
        ipc.io(handle, 'write', b'ACK', timeout_ms=timeout)
        return ipc.parse(response)
    finally:
        win.close(handle)


def client(cfg):
    out = Path(cfg['out'])
    (out/'scratch').write_bytes(b'positive')
    result = {'completed': True}
    try:
        if cfg.get('preconnect_barrier'):
            ready = out/'preconnect-ready.json'; release = out/'preconnect-release'
            save(ready, {'pid': os.getpid(), 'state': 'READY_TO_CONNECT'})
            deadline = time.monotonic()+float(cfg.get('preconnect_timeout_seconds', 20))
            while not release.exists() and time.monotonic() < deadline:
                time.sleep(.005)
            if not release.exists(): raise TimeoutError('CLIENT_RELEASE_TIMEOUT')
        result['response'] = client_exchange(cfg)
    except Exception as exc:
        result.update(error=type(exc).__name__+': '+str(exc), winerror=getattr(exc, 'winerror', None))
    save(out/'client.json', result)


if __name__ == '__main__':
    cfg = json.loads(Path(sys.argv[1]).read_bytes())
    try:
        {'server': server, 'client': client, 'probe': probe}[cfg['role']](cfg)
    except Exception as exc:
        save(Path(cfg['root'])/'journal/fatal.json', {
            'error': type(exc).__name__+': '+str(exc),
        })
        raise
