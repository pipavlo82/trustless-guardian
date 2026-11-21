"""Long-budget v04 worker for the PR2 ordinary-exception transition witness."""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import sqlite3
import sys

from guardian import ipc
from guardian import windows as win
from guardian.hardened import refusal
from guardian.policy import canonical, digest
import v03_worker as worker
from v04_worker import InstrumentedBroker


def server(cfg):
    out = Path(cfg['root'])/'journal'; prefix = cfg.get('fixture_channel', '')
    rows = []; locks = []
    broker = InstrumentedBroker(cfg)
    pipe = ipc.Server(cfg['pipe_local'], cfg['broker_sid'],
                      cfg.get('fixture_pipe_sid', cfg['agent_sid']),
                      win.token_info()['user_sid'])
    worker.save(out/(prefix+'ready.json'), {
        'pid': os.getpid(), 'dacl': worker.pipe_descriptor(pipe.handle),
    })
    timeout = int(cfg.get('timeout_ms', 15000))
    response_timeout = int(cfg.get('response_timeout_ms', 15000))
    try:
        for _ in range(cfg.get('connections', 1)):
            connected = False; identity = None
            try:
                ipc.io(pipe.handle, 'connect', timeout_ms=timeout); connected = True
                raw = ipc.io(pipe.handle, 'read', timeout_ms=timeout)
                identity = ipc.authenticate(pipe.handle, cfg['agent_sid'], cfg['user_sha256'])
                response = broker.execute(raw, identity['appcontainer_sid'],
                                          cfg.get('fixture_time', 1000))
                row = {'response': response, 'identity': identity,
                       'request_sha256': digest(raw)}
            except Exception as exc:
                response = refusal(type(exc).__name__+': '+str(exc),
                                   'UNVERIFIABLE' if isinstance(exc, OSError) else 'REFUTED')
                row = {'response': response, 'transport_error': True}
            finally:
                for db in locks:
                    db.rollback(); db.close()
                locks.clear()
            row['thread_after_auth'] = worker.thread_token(); rows.append(row)
            worker.save(out/(prefix+'server.json'), rows)
            if connected:
                try:
                    ipc.io(pipe.handle, 'write', canonical(response), timeout_ms=response_timeout)
                    ipc.io(pipe.handle, 'read', timeout_ms=response_timeout)
                except (OSError, TimeoutError, ValueError):
                    pass
                win.check(win.api(win.k, 'DisconnectNamedPipe', w.BOOL, w.HANDLE)(pipe.handle))
    finally:
        pipe.close(); broker.close()


def client(cfg):
    out = Path(cfg['out']); (out/'scratch').write_bytes(b'positive')
    result = {'completed': True}; handle = None
    timeout = int(cfg.get('client_timeout_ms', 15000))
    try:
        handle = ipc.connect(cfg['pipe'], cfg['server_pid'])
        ipc.io(handle, 'write', bytes.fromhex(cfg['raw_hex']), timeout_ms=timeout)
        result['response'] = ipc.parse(ipc.io(handle, 'read', timeout_ms=timeout))
        ipc.io(handle, 'write', b'ACK', timeout_ms=timeout)
    except Exception as exc:
        result.update(error=type(exc).__name__+': '+str(exc),
                      winerror=getattr(exc, 'winerror', None))
    finally:
        if handle:
            win.close(handle)
        worker.save(out/'client.json', result)


if __name__ == '__main__':
    config = json.loads(Path(sys.argv[1]).read_bytes())
    try:
        {'server': server, 'client': client, 'probe': worker.probe}[config['role']](config)
    except Exception:
        import traceback
        worker.save(Path(config['root'])/'journal/fatal.json', {
            'control_broken': traceback.format_exc(),
        })
        raise
