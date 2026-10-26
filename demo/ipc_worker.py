"""Lab-only IPC timing profile; native auth, schema and resource checks unchanged.

The host performs independent observations around each operation. The historical
worker's 700ms ACK / 1800ms connect budgets are not suitable under concurrent
audit I/O. Use a bounded 8s operation deadline here, never retry an operation.
"""
from pathlib import Path
import runpy
from guardian import ipc

original_io = ipc.io


def laboratory_io(handle, operation, data=b'', timeout_ms=3000):
    return original_io(handle, operation, data, timeout_ms=max(timeout_ms, 8000))


ipc.io = laboratory_io
runpy.run_path(str(Path(__file__).with_name('v04_worker.py')), run_name='__main__')
