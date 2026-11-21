"""Barrier-enabled v02 client used only by the PR1 availability transition."""
import json
import os
from pathlib import Path
import sys
import time

from v02_worker import client as original_client
from v02_worker import probe, save, server


def client(cfg):
    if not cfg.get('preconnect_barrier'):
        return original_client(cfg)
    out = Path(cfg['out'])
    (out/'scratch').write_bytes(b'positive')
    ready = out/'preconnect-ready.json'
    release = out/'preconnect-release'
    save(ready, {'pid': os.getpid(), 'state': 'READY_TO_CONNECT'})
    deadline = time.monotonic()+float(cfg.get('preconnect_timeout_seconds', 8))
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(.005)
    if not release.exists():
        save(out/'client.json', {
            'completed': True,
            'error': 'TimeoutError: CLIENT_RELEASE_TIMEOUT',
            'winerror': None,
        })
        return
    original_client(cfg)


if __name__ == '__main__':
    cfg = json.loads(Path(sys.argv[1]).read_bytes())
    try:
        {'server': server, 'client': client, 'probe': probe}[cfg['role']](cfg)
    except Exception as exc:
        save(Path(cfg['root'])/'journal/fatal.json', {
            'error': type(exc).__name__+': '+str(exc),
        })
        raise
