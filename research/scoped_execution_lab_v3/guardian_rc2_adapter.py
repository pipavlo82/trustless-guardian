"""Run the RC2 intent through the frozen native Guardian laboratory on Windows."""
from __future__ import annotations

import argparse
import hashlib
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

GUARDIAN_ROOT = Path(__file__).resolve().parents[2]
BASELINE_ROOT = GUARDIAN_ROOT
GUARDIAN_COMMIT = "13d4d7819db5bdc412f64d4f7752fe7c2b199af8"
SERVER = Path(__file__).with_name("guardian_rc2_server.py")
sys.path.insert(0, str(GUARDIAN_ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from guardian.windows import Container, acl, low_label
from research.guardian_mutual_ipc_v1.native import package
from research.guardian_mutual_ipc_v1.protocol import encode


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha_file(path: Path) -> str:
    return sha(path.read_bytes())


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def run(out_path: str | Path, intent_path: str | Path) -> dict:
    out = Path(out_path).resolve()
    intent_file = Path(intent_path).resolve()
    out.mkdir(parents=True, exist_ok=False)
    intent_raw = intent_file.read_bytes()
    intent = json.loads(intent_raw)
    if intent_raw != canonical(intent) + b"\n":
        raise RuntimeError("RC2_INTENT_NONCANONICAL")
    intent_sha256 = sha(canonical(intent))
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=BASELINE_ROOT,
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    # The release candidate is an additive branch derived from the pinned baseline.
    # Record its actual commit; do not falsely represent it as the frozen baseline.

    root = Path(tempfile.mkdtemp(prefix="guardian-lab-resonance-rc2-"))
    container = None
    proc = None
    result = {
        "schema": "resonance.rc2.native-guardian-run.v1",
        "status": "CONTROL_BROKEN",
        "scope": "NATIVE_WINDOWS_LOCAL_LAB_ONLY",
        "guardian_commit": head,
        "intent_sha256": intent_sha256,
        "started_at": int(time.time()),
    }
    try:
        key = Ed25519PrivateKey.generate()
        now = int(time.time())
        trust = {
            "schema": "guardian.broker-trust.v1",
            "broker_id": "guardian-lab",
            "trust_root_version": "lab-root-v1",
            "key_id": "lab-ed25519",
            "public_key": key.public_key().public_bytes_raw().hex(),
            "revoked": False,
            "not_before": now - 5,
            "expires_at": now + 1800,
        }
        runtime = package(root, trust)
        client = runtime / "client.py"
        original_client = client.read_bytes()
        old = b"session = ClientSession(trust, channel, int(time.time()))"
        new = b"session = ClientSession(trust, channel, int(time.time()), session_id=Path(__file__).with_name('rc2-intent-sha256.txt').read_text('ascii'))"
        if original_client.count(old) != 1:
            raise RuntimeError("GUARDIAN_CLIENT_ADAPTER_POINT_DRIFT")
        client.write_bytes(original_client.replace(old, new))
        (runtime / "rc2-intent-sha256.txt").write_bytes(intent_sha256.encode("ascii"))
        result["runtime_adapter"] = {
            "original_client_sha256": sha(original_client),
            "adapted_client_sha256": sha_file(client),
            "change": "ClientSession.session_id equals canonical Core V2 intent SHA-256",
            "authority_change": False,
        }

        diagnostic = root / "client-io.json"
        diagnostic.write_bytes(b"")
        protected = out / "protected-state-sentinel.txt"
        protected.write_bytes(b"PUBLIC_SYNTHETIC_PROTECTED_SENTINEL\n")
        probe = runtime / "probe.py"
        probe.write_bytes(
            b"import sys,json,ctypes as c\n"
            b"from ctypes import wintypes as w\nfrom pathlib import Path\n"
            b"k=c.WinDLL('kernel32',use_last_error=True)\n"
            b"f=k.CreateFileW;f.restype=w.HANDLE;f.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE]\n"
            b"k.CloseHandle.argtypes=[w.HANDLE]\nr={}\n"
            b"for mode,access in [('rb',0x80000000),('wb',0x40000000)]:\n"
            b" h=f(sys.argv[1],access,0,None,3,0,None)\n"
            b" if h==c.c_void_p(-1).value:r[mode]=c.get_last_error()\n"
            b" else:r[mode]='UNEXPECTED_ACCESS';k.CloseHandle(h)\n"
            b"Path(sys.argv[2]).write_text(json.dumps(r))\n"
            b"raise SystemExit(0 if r=={'rb':5,'wb':5} else 1)\n"
        )

        container = Container("resonance-rc2-" + uuid.uuid4().hex[:12])
        sid = container.principal
        for path in [root, runtime, *runtime.rglob("*")]:
            acl(root, path, sid, writable=False)
        acl(root, diagnostic, sid, writable=True)
        low_label(root, root)
        probe_run = container.launch(
            [str(runtime / "python.exe"), "-I", "-B", str(probe), str(protected), str(diagnostic)],
            root, timeout=15,
        )
        access = json.loads(diagnostic.read_bytes())
        result["protected_probe"] = {
            "process": probe_run,
            "access": access,
            "unchanged": protected.read_bytes() == b"PUBLIC_SYNTHETIC_PROTECTED_SENTINEL\n",
        }
        if probe_run["exit_code"] != 0 or access != {"rb": 5, "wb": 5} or not result["protected_probe"]["unchanged"]:
            raise RuntimeError("PROTECTED_RESOURCE_BOUNDARY_FAILED")
        diagnostic.write_bytes(b"")

        trust_file = out / "broker-public-trust.json"
        trust_file.write_bytes(encode(trust) + b"\n")
        intent_copy = out / "intent.json"
        intent_copy.write_bytes(intent_raw)
        channel = "guardian-resonance-" + secrets.token_hex(12)
        args = [
            sys.executable, "-B", str(SERVER), "--channel", channel, "--sid", sid,
            "--ready", str(out / "ready"), "--out", str(out), "--trust", str(trust_file),
            "--intent", str(intent_copy),
        ]
        proc = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=BASELINE_ROOT, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        proc.stdin.write(encode({"key": key.private_bytes_raw().hex()}) + b"\n")
        proc.stdin.close()
        proc.stdin = None
        for _ in range(200):
            if (out / "ready").exists() or proc.poll() is not None:
                break
            time.sleep(0.05)
        if not (out / "ready").exists():
            raise RuntimeError("GUARDIAN_BROKER_NOT_READY")
        observed = container.launch(
            [str(runtime / "python.exe"), "-I", "-B", str(client), channel, "normal", str(diagnostic)],
            root, timeout=20,
        )
        stdout, stderr = proc.communicate(timeout=55)
        (out / "guardian-server.stdout").write_bytes(stdout)
        (out / "guardian-server.stderr").write_bytes(stderr)
        result.update(
            broker_pid=proc.pid,
            appcontainer_sid=sid,
            channel_id=channel,
            client=observed,
            client_io=json.loads(diagnostic.read_bytes()),
            broker_exit=proc.returncode,
            execution=json.loads((out / "execution.json").read_bytes()),
            status="OBSERVED" if proc.returncode == 0 else "CONTROL_BROKEN",
        )
    except Exception as error:
        result.update(error=type(error).__name__, reason=str(error), status="CONTROL_BROKEN")
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=5)
        if container is not None:
            container.close()
        shutil.rmtree(root, ignore_errors=True)
        result["temporary_root_deleted"] = not root.exists()
        result["finished_at"] = int(time.time())
        (out / "native.json").write_bytes(canonical(result) + b"\n")
    print(json.dumps(result, sort_keys=True))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--intent", required=True)
    values = parser.parse_args()
    observed = run(values.out, values.intent)
    raise SystemExit(0 if observed["status"] == "OBSERVED" else 2)
