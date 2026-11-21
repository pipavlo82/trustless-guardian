"""PR1 replacement witness: attempt denial only while the broker is provably live."""
from pathlib import Path
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import shutil
import subprocess
import sys
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n', encoding='utf-8', newline='\n')


def run(out, frozen, mode):
    out = out.resolve(); frozen = frozen.resolve()
    if out.exists(): raise ValueError('fresh output directory required')
    out.mkdir(parents=True)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=frozen, text=True).strip()
    if head != '03f6ffc6f4b983cfcc39f401f47165021e67e673':
        raise ValueError('FROZEN_SHA_REFUSED')
    sys.path.insert(0, str(frozen))
    from guardian import windows as win
    from guardian.policy import canonical, digest
    from tools.lab import write
    from tools.v02_campaign import allowed
    from tools.v02_lab import Lab02

    class AvailabilityLab(Lab02):
        def initialize(self, target, extra_actor):
            super().initialize(target, extra_actor)
            shutil.copyfile(HERE/'pr1_availability_worker_v1.py', self.runtime/'pr1_availability_worker_v1.py')
            self.acl(self.runtime/'pr1_availability_worker_v1.py')

        def launch(self, container, cfg, name):
            config = self.runtime/(name+'.json'); write(config, cfg); self.acl(config)
            result = container.launch([
                self.runtime/'python.exe', '-B', *(['-O'] if sys.flags.optimize else []),
                self.runtime/'pr1_availability_worker_v1.py', config,
            ], self.runtime, 20)
            result['token']['user_sid_sha256'] = digest(result['token'].pop('user_sid').encode())
            write(self.out/(name+'.process.json'), result)
            return result

        def broker_active(self):
            code = w.DWORD()
            win.check(win.api(win.k, 'GetExitCodeProcess', w.BOOL, w.HANDLE, c.POINTER(w.DWORD))(
                self.handle, c.byref(code)))
            return code.value == 259

        def synchronized_other(self, name, value, server_options=None):
            before = self.resource.read_bytes()
            # Preparing ACLs/config before broker start removes host setup from the pipe budget.
            client_out = self.root/('client-'+uuid.uuid4().hex); client_out.mkdir()
            self.acl(client_out, broker=None, agent=None, other='FA'); win.low_label(self.root, client_out)
            self.start(name, **(server_options or {}))
            cfg = {
                'root': str(self.root), 'role': 'client', 'out': str(client_out),
                'pipe': self.pipe, 'server_pid': self.pid,
                'raw_hex': canonical(value).hex(), 'preconnect_timeout_seconds': 8,
                'preconnect_barrier': True,
            }
            ready = client_out/'preconnect-ready.json'; release = client_out/'preconnect-release'
            holder = {}; errors = []
            def launch_client():
                try: holder['process'] = self.launch(self.other, cfg, name+'-client')
                except Exception as exc: errors.append(type(exc).__name__+': '+str(exc))
            client_thread = threading.Thread(target=launch_client); client_thread.start()
            deadline = time.monotonic()+8
            while time.monotonic() < deadline and client_thread.is_alive() and not ready.exists():
                time.sleep(.005)
            worker_ready = ready.exists()
            server_thread_alive = bool(self.thread and self.thread.is_alive())
            server_process_alive = self.broker_active() if self.handle else False
            released = worker_ready and server_thread_alive and server_process_alive
            if released: release.write_bytes(b'release\n')
            else:
                # Unblock the child for cleanup, but retain released=False in the witness.
                release.write_bytes(b'cleanup\n')
            client_thread.join(20)
            if client_thread.is_alive(): errors.append('CLIENT_THREAD_HUNG')
            response = json.loads((client_out/'client.json').read_bytes()) if (client_out/'client.json').is_file() else None
            server = self.finish(name)
            after = self.resource.read_bytes()
            row = {
                'name': name, 'response': response, 'server_exit': server.get('exit_code'),
                'before_sha256': digest(before), 'after_sha256': digest(after),
                'unchanged': before == after, 'worker_ready': worker_ready,
                'server_thread_alive_at_release': server_thread_alive,
                'server_process_alive_at_release': server_process_alive,
                'released_while_available': released, 'client_errors': errors,
                'client_process': holder.get('process'),
            }
            write(self.out/(name+'.availability.json'), row)
            return row

    lab = AvailabilityLab(out/'lab')
    try:
        positive = lab.roundtrip('positive', server_options={'timeout_ms': 5000})
        denied = lab.synchronized_other(
            'unauthorized_available', lab.request('unauthorized_available'),
            {'timeout_ms': 5000},
        )
        acl_removed = lab.synchronized_other(
            'pipe_acl_removed', lab.request('pipe_acl_removed'),
            {'timeout_ms': 5000, 'fixture_pipe_sid': lab.other.principal},
        )
        denial_pass = (
            denied['released_while_available'] and denied['unchanged'] and not denied['client_errors']
            and denied['response'] is not None and denied['response'].get('winerror') == 5
        )
        removed_response = (acl_removed.get('response') or {}).get('response', {})
        control_killed = (
            acl_removed['released_while_available'] and acl_removed['unchanged']
            and not acl_removed['client_errors'] and acl_removed['response'] is not None
            and acl_removed['response'].get('winerror') != 5
            and 'IPC_CALLER' in removed_response.get('reason', '')
        )
        cases = [
            {'name': 'healthy_agent', 'result': 'PASS' if allowed(positive) else 'FAIL'},
            {'name': 'unauthorized_available_pipe', 'result': 'PASS' if denial_pass else 'FAIL'},
            {'name': 'pipe_acl_removal', 'result': 'KILLED' if control_killed else 'SURVIVED_OR_CONTROL_BROKEN'},
        ]
        passed = allowed(positive) and denial_pass and control_killed
        report = {
            'schema': 'guardian.pr1-availability-witness.v1', 'passed': passed,
            'frozen_sha': head, 'mode': mode,
            'cases': cases, 'positive': positive, 'unauthorized': denied,
            'physical_control': acl_removed,
            'meaning': 'WinError5 counts only when the preinitialized client was released while the broker process and host supervisor thread were live.',
            'production': 'HOLD', 'external_review': 'NOT_ESTABLISHED',
            'source_sha256': {
                'tools/pr1_availability_worker_v1.py': sha((HERE/'pr1_availability_worker_v1.py').read_bytes()),
                'tools/pr1_availability_witness_v1.py': sha(Path(__file__).read_bytes()),
            },
        }
        save(out/'report.json', report)
        return report
    finally:
        lab.close()


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--out', type=Path, required=True); p.add_argument('--frozen', type=Path, required=True)
    p.add_argument('--mode', choices=('normal', 'repeat', 'optimized'), required=True); a = p.parse_args()
    raise SystemExit(0 if run(a.out, a.frozen, a.mode)['passed'] else 1)
