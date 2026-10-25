"""Direct executable launch in an ephemeral, zero-capability AppContainer.

Lab-only launcher. Does not alter the Guardian core's process-launch contract.
Only three explicitly selected synthetic stdio handles are inherited. No user
environment/config/credentials are passed. A single-process job kills on close.
"""
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import threading
import msvcrt

from guardian import windows as win


class SECURITY_ATTRIBUTES(c.Structure):
    _fields_ = [('size', w.DWORD), ('descriptor', win.P), ('inherit', w.BOOL)]


def run(container, executable, args, project, home, out, relay, timeout=120):
    executable, project, home, out = map(Path, (executable, project, home, out))
    out.mkdir()
    api, check = win.api, win.check
    handles = []
    attrs = None
    job = None
    pi = win.PROCESSINFO()
    streams = []; host_handles = []; frames = []; relay_errors = []
    row = {'schema': 'guardian.runtime-launch.v06',
           'image_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
           'arguments': args, 'network_capabilities': [], 'process_limit': 1,
           'credential_source': 'NONE', 'profile_source': 'EMPTY_DISPOSABLE_HOME',
           'inherited_handles_policy': 'EXPLICIT_SYNTHETIC_STDIO_ONLY'}
    try:
        sa = SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES), None, True)
        create_file = api(win.k, 'CreateFileW', w.HANDLE, w.LPCWSTR, w.DWORD,
                          w.DWORD, c.POINTER(SECURITY_ATTRIBUTES), w.DWORD, w.DWORD, w.HANDLE)
        create_pipe = api(win.k, 'CreatePipe', w.BOOL, c.POINTER(w.HANDLE), c.POINTER(w.HANDLE), c.POINTER(SECURITY_ATTRIBUTES), w.DWORD)
        set_flags = api(win.k, 'SetHandleInformation', w.BOOL, w.HANDLE, w.DWORD, w.DWORD)
        for child_read in (True, False):
            read, write = w.HANDLE(), w.HANDLE()
            check(create_pipe(c.byref(read), c.byref(write), c.byref(sa), 0))
            child, host = (read.value, write.value) if child_read else (write.value, read.value)
            check(set_flags(host, 1, 0)); handles.append(child); host_handles.append(host)
        for name, access in [('stderr.log', 0x40000000)]:
            (out / name).write_bytes(b'')
            handle = create_file(str(out / name), access, 3, c.byref(sa), 3, 0x80, None)
            check(handle != c.c_void_p(-1).value)
            handles.append(handle)
        init = api(win.k, 'InitializeProcThreadAttributeList', w.BOOL, win.P, w.DWORD, w.DWORD, c.POINTER(win.SIZE))
        update = api(win.k, 'UpdateProcThreadAttribute', w.BOOL, win.P, w.DWORD, win.SIZE, win.P, win.SIZE, win.P, win.P)
        size = win.SIZE(); init(None, 2, 0, c.byref(size))
        attrs = c.create_string_buffer(size.value); check(init(attrs, 2, 0, c.byref(size)))
        caps = win.CAPABILITIES(container.sid, None, 0, 0)
        check(update(attrs, 0, 0x20009, c.byref(caps), c.sizeof(caps), None, None))
        selected = (w.HANDLE * 3)(*handles)
        check(update(attrs, 0, 0x20002, selected, c.sizeof(selected), None, None))
        si = win.STARTUPINFOEX(); si.StartupInfo.cb = c.sizeof(si)
        si.lpAttributeList = c.cast(attrs, win.P); si.StartupInfo.dwFlags = 0x100
        si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = handles
        # Deliberately no inherited authentication, plugin, telemetry or proxy settings.
        values = {'SystemRoot': os.environ['SystemRoot'], 'WINDIR': os.environ['SystemRoot'],
                  'PATH': str(Path(os.environ['SystemRoot']) / 'System32'),
                  'USERPROFILE': str(home), 'HOME': str(home), 'CODEX_HOME': str(home),
                  'LOCALAPPDATA': str(home), 'APPDATA': str(home),
                  'TEMP': str(home), 'TMP': str(home), 'NO_COLOR': '1'}
        values.update(HERMES_HOME=str(home), HERMES_SKIP_DOTENV='1', PYTHONIOENCODING='utf-8', PYTHONDONTWRITEBYTECODE='1')
        env = c.create_unicode_buffer('\0'.join(k+'='+v for k,v in sorted(values.items()))+'\0\0')
        job = api(win.k, 'CreateJobObjectW', w.HANDLE, win.P, w.LPCWSTR)(None, None); check(job)
        limits = win.EXTENDED_LIMIT(); limits.basic.flags = 0x2000 | 8; limits.basic.active_processes = 1
        check(api(win.k, 'SetInformationJobObject', w.BOOL, w.HANDLE, c.c_int, win.P, w.DWORD)(job, 9, c.byref(limits), c.sizeof(limits)))
        command = c.create_unicode_buffer(subprocess.list2cmdline([str(executable), *args]))
        create = api(win.k, 'CreateProcessW', w.BOOL, w.LPCWSTR, w.LPWSTR, win.P, win.P, w.BOOL, w.DWORD, win.P, w.LPCWSTR, c.POINTER(win.STARTUPINFOEX), c.POINTER(win.PROCESSINFO))
        check(create(str(executable), command, None, None, True, 0x80000 | 4 | 0x08000000 | 0x400,
                     env, str(project), c.byref(si), c.byref(pi)))
        check(api(win.k, 'AssignProcessToJobObject', w.BOOL, w.HANDLE, w.HANDLE)(job, pi.hProcess))
        row['pid'] = pi.dwProcessId
        # Independent process: no Guardian imports; observes the actual Codex PID,
        # token, executable path digest, and process handle table before resume.
        argv = [sys.executable, '-B', str(Path(__file__).resolve().parents[1]/'verify_demo.py'),
                '--pid', str(pi.dwProcessId), '--out', str(out/'native.json')]
        observer = subprocess.run(argv, capture_output=True)
        (out/'observer.stdout').write_bytes(observer.stdout); (out/'observer.stderr').write_bytes(observer.stderr)
        row['observer_exit'] = observer.returncode
        if observer.returncode: raise RuntimeError('INDEPENDENT_PROCESS_OBSERVER_FAILED')
        native = json.loads((out/'native.json').read_bytes()); token = native['token']
        if not (token['appcontainer'] and token['appcontainer_sid'] == container.principal and
                token['integrity_sid'] == 'S-1-16-4096' and not token['elevated'] and token['capability_count'] == 0):
            raise RuntimeError('RUNTIME_TOKEN_MISMATCH')
        if native['image_sha256'] != row['image_sha256']: raise RuntimeError('RUNTIME_IMAGE_MISMATCH')
        observed = {item['handle'] for item in native['handles']}
        row['selected_stdio_handles'] = handles
        row['unexpected_handles'] = sorted(observed-set(handles))
        if row['unexpected_handles']: raise RuntimeError('UNEXPECTED_INHERITED_HANDLE')
        writer = os.fdopen(msvcrt.open_osfhandle(host_handles[0], os.O_WRONLY | os.O_BINARY), 'wb', buffering=0)
        reader = os.fdopen(msvcrt.open_osfhandle(host_handles[1], os.O_RDONLY | os.O_BINARY), 'rb', buffering=0)
        streams = [writer, reader]; host_handles = []
        def pump():
            from protocol import LIMIT, decode
            try:
                while True:
                    raw = reader.readline(LIMIT+1)
                    if not raw: break
                    value = decode(raw); frames.append(value)
                    reply = relay(value)
                    if reply is not None:
                        encoded = json.dumps(reply).encode()+b'\n'
                        if len(encoded)>LIMIT: raise ValueError('REPLY_SIZE')
                        writer.write(encoded)
            except Exception as exc:
                relay_errors.append(type(exc).__name__+': '+str(exc))
                api(win.k, 'TerminateProcess', w.BOOL, w.HANDLE, w.UINT)(pi.hProcess, 97)
        thread = threading.Thread(target=pump, daemon=True); thread.start()
        start = time.perf_counter()
        result = api(win.k, 'ResumeThread', w.DWORD, w.HANDLE)(pi.hThread)
        if result == 0xffffffff: raise c.WinError(c.get_last_error())
        # Close host duplicates of the CHILD ends; only the confined process owns
        # them now. EOF is observable and no host handle enters the child.
        for h in handles: win.close(h)
        handles = []
        row['resume_previous_count'] = result
        waited = api(win.k, 'WaitForSingleObject', w.DWORD, w.HANDLE, w.DWORD)(pi.hProcess, timeout*1000)
        row['timed_out'] = waited == 258
        if waited != 0:
            check(api(win.k, 'TerminateProcess', w.BOOL, w.HANDLE, w.UINT)(pi.hProcess, 98))
            check(api(win.k, 'WaitForSingleObject', w.DWORD, w.HANDLE, w.DWORD)(pi.hProcess, 5000) == 0)
        code = w.DWORD(); check(api(win.k, 'GetExitCodeProcess', w.BOOL, w.HANDLE, c.POINTER(w.DWORD))(pi.hProcess, c.byref(code)))
        row.update(exit_code=code.value, seconds=time.perf_counter()-start, confinement_observed=True)
        thread.join(5)
        row.update(relay_errors=relay_errors, relay_thread_finished=not thread.is_alive(),
                   model_requests=relay.calls, frames=frames)
    except Exception as exc:
        row.update(error=type(exc).__name__+': '+str(exc), confinement_observed=False)
    finally:
        # Job close always terminates any remaining member, including suspended errors.
        if job: win.close(job)
        if pi.hThread: win.close(pi.hThread)
        if pi.hProcess: win.close(pi.hProcess)
        if attrs: api(win.k, 'DeleteProcThreadAttributeList', None, win.P)(attrs)
        for handle in handles: win.close(handle)
        for handle in host_handles: win.close(handle)
        for stream in streams: stream.close()
    (out/'launch.json').write_bytes(json.dumps(row, sort_keys=True, indent=2).encode()+b'\n')
    return row
