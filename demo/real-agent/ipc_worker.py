"""Lab-only bounded inference wait. Core IPC predicates remain unchanged."""
from pathlib import Path
import json
import sys
import time
from guardian import ipc

original = ipc.io
def bounded(handle, operation, *args, **kwargs):
    kwargs['timeout_ms'] = 110000 if operation == 'connect' else 8000
    return original(handle, operation, *args, **kwargs)
ipc.io = bounded
import v04_worker as faults
class ClockBroker(faults.InstrumentedBroker):
    def execute(self, raw, principal, unused_fixture_clock, hook=lambda *a: None):
        return super().execute(raw, principal, int(time.time()), hook)
faults.worker.HardenedBroker = ClockBroker
cfg = json.loads(Path(sys.argv[1]).read_bytes())
{'server': faults.worker.server, 'client': faults.worker.client, 'probe': faults.worker.probe}[cfg['role']](cfg)
