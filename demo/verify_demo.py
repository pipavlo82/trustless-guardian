"""Separate standard-library verifier. NO Guardian policy/broker/IPC imports.

Native observations are trusted host measurements, not remote attestations.
Portable checks cannot by themselves establish a real-agent run.
"""
import argparse
import base64
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def snapshot(paths):
    result = {}
    for name, location in paths.items():
        path = Path(location)
        with path.open('rb') as stream:
            import os
            before = os.fstat(stream.fileno()); raw = stream.read(); after = os.fstat(stream.fileno())
            import msvcrt
            class INFO(c.Structure):
                _fields_ = [('attributes', w.DWORD), ('created', w.FILETIME), ('accessed', w.FILETIME),
                            ('written', w.FILETIME), ('volume', w.DWORD), ('size_high', w.DWORD),
                            ('size_low', w.DWORD), ('links', w.DWORD), ('index_high', w.DWORD), ('index_low', w.DWORD)]
            info = INFO(); kernel = c.WinDLL('kernel32', use_last_error=True)
            f = kernel.GetFileInformationByHandle; f.argtypes = [w.HANDLE, c.POINTER(INFO)]; f.restype = w.BOOL
            if not f(msvcrt.get_osfhandle(stream.fileno()), c.byref(info)): raise c.WinError(c.get_last_error())
        if (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns):
            raise RuntimeError('RESOURCE_CHANGED_DURING_OBSERVATION')
        result[name] = {'sha256': sha(raw), 'hex': raw.hex(), 'identity': [info.volume, info.index_high, info.index_low]}
    return result


def observe_process(pid):
    from tools.v04_native import process, api, K, close, check
    token = process(pid)
    handle = api(K, 'OpenProcess', w.HANDLE, w.DWORD, w.BOOL, w.DWORD)(0x1400, False, pid); check(handle)
    try:
        size = w.DWORD(32768); name = c.create_unicode_buffer(size.value)
        check(api(K, 'QueryFullProcessImageNameW', w.BOOL, w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD))(handle, 0, name, c.byref(size)))
        class ENTRY(c.Structure):
            _fields_ = [('handle', w.HANDLE), ('handle_count', c.c_size_t), ('pointer_count', c.c_size_t),
                        ('access', w.DWORD), ('type', w.DWORD), ('attributes', w.DWORD), ('reserved', w.DWORD)]
        query = api(c.WinDLL('ntdll'), 'NtQueryInformationProcess', c.c_long, w.HANDLE, w.DWORD, c.c_void_p, w.ULONG, c.POINTER(w.ULONG))
        buf = c.create_string_buffer(131072); returned = w.ULONG()
        status = query(handle, 51, buf, len(buf), c.byref(returned))
        if status < 0: raise OSError('PROCESS_HANDLE_SNAPSHOT_UNAVAILABLE '+hex(status & 0xffffffff))
        count = c.c_size_t.from_buffer(buf).value
        offset = 2*c.sizeof(c.c_size_t)
        if offset+count*c.sizeof(ENTRY)>len(buf): raise RuntimeError('HANDLE_SNAPSHOT_SIZE')
        entries = (ENTRY*count).from_buffer(buf, offset)
        return {'token': token, 'image_sha256': sha(Path(name.value).read_bytes()),
                'handles': [{'handle': e.handle, 'access': e.access, 'type': e.type, 'attributes': e.attributes} for e in entries]}
    finally: close(handle)


def verify(value):
    rows = value['controls']; checks = {}
    original = value['policy']; policy_sha = sha(canonical(original))
    checks['policy_preimage'] = policy_sha == value['policy_sha256'] == rows['ALLOW']['before']['policy']['sha256']
    for name, row in rows.items():
        # The observer opens files separately before/after, outside both containers.
        checks[name+'_snapshots'] = all(sha(bytes.fromhex(s['hex'])) == s['sha256'] for snap in (row['before'], row['after']) for s in snap.values())
        checks[name+'_identities'] = all(row['before'][key]['identity'] == row['after'][key]['identity'] for key in row['before'])
        checks[name+'_protected'] = all(row['before'][key] == row['after'][key] for key in ('config', 'secret'))
    a = rows['ALLOW']; reply = a['response']; req = a['request']['request']
    checks['allow_request'] = (req['actor'] == value['agent_sid'] and req['actor'] in original['actors'] and
        req['action'] == original['action'] == 'replace_utf8' and req['resource'] == original['resource'] and
        req['scope'] == original['scope'] and req['policy_version'] == original['version'] and
        a['request']['policy_sha256'] == policy_sha and req['content'] == 'approved:demo-source' and
        req['evidence'] == {'before_sha256': a['before']['source']['sha256']} and 1000 <= req['expires_at'] <= 1060)
    checks['allow_outcome'] = reply.get('status') == 'VERIFIED' and reply.get('decision') == 'ALLOW' and reply.get('execution') == 'COMMITTED'
    checks['allow_bytes'] = a['after']['source']['hex'] == b'approved:demo-source'.hex()
    receipt = reply.get('receipt', {}); body = receipt.get('body', {})
    checks['receipt_digest'] = bool(body) and receipt.get('previous') == '0'*64 and sha(canonical({'previous': receipt.get('previous'), 'body': body})) == receipt.get('sha256')
    checks['receipt_bindings'] = (body.get('request') == req and body.get('policy_sha256') == policy_sha and
        body.get('request_sha256') == sha(canonical(req)) and body.get('before_sha256') == a['before']['source']['sha256'] and
        body.get('after_sha256') == a['after']['source']['sha256'] and body.get('principal') == value['agent_sid'] and
        body.get('resource_identity') == a['before']['source']['identity'] == a['after']['source']['identity'])
    checks['allow_ipc_identity'] = all(a['ipc_identity'].get(k) == v for k,v in {
        'appcontainer_sid': value['agent_sid'], 'capability_count': 0, 'elevated': False,
        'integrity_sid': 'S-1-16-4096', 'impersonation_level': 1}.items())
    d = rows['DENY']; checks['deny'] = d['response'].get('status') == 'REFUTED' and d['response'].get('decision') == 'DENY' and d['before'] == d['after']
    b = rows['BYPASS']; checks['bypass'] = b['before'] == b['after'] and len(b['attempts']) == 6 and all(x.get('result') == 'OS_REJECTED' and x.get('winerror') == 5 for x in b['attempts'])
    checks['bypass_positive'] = b['scratch_positive'] is True
    p = rows['POLICY_CHANGE']; checks['policy_change'] = p['response'].get('decision') == 'DENY' and p['response'].get('status') == 'REFUTED' and p['before'] == p['after'] and value['agent_sid'] not in value['changed_policy']['actors']
    r = rows['RECOVERY']; checks['recovery'] = (r['after']['source']['hex'] == b'approved:ambiguous'.hex() and
        r['response'].get('status') == 'UNVERIFIABLE' and r['response'].get('execution') == 'RECOVERY_REQUIRED' and
        r['response'].get('retry_permitted') is False and r['journal_state'] == 'PREPARED')
    checks['no_real_agent_promotion'] = value['real_agent_status'] == 'NOT_COVERED' and value['client_kind'] == 'SCRIPTED_OS_CONTROL'
    return {'schema': 'guardian.demo-verification.v05', 'checks': checks, 'laboratory_passed': all(checks.values()),
            'real_agent_status': 'NOT_COVERED', 'production_ready': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--pid', type=int); p.add_argument('--files', type=Path)
    p.add_argument('--input', type=Path); p.add_argument('--out', type=Path, required=True); a = p.parse_args()
    if a.pid: result = observe_process(a.pid)
    elif a.files: result = snapshot(json.loads(a.files.read_bytes()))
    elif a.input: result = verify(json.loads(a.input.read_bytes()))
    else: p.error('one observation mode required')
    a.out.write_bytes(json.dumps(result, sort_keys=True, indent=2).encode()+b'\n')
    raise SystemExit(0 if result.get('laboratory_passed', True) else 1)
