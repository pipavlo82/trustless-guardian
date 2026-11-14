"""Real local Windows AppContainer controls. No Docker worker or execution grant."""
import argparse
import hashlib
import importlib.metadata
import importlib.util
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
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from research.guardian_mutual_ipc_v1.protocol import encode, ClientSession

HERE = Path(__file__).resolve().parent
OLD = ROOT / "research/resonance_guardian_v1"
BASE = "2a40075a7f217e9c385cdfaf27c0267fa788d574"
CORE_SHA = "6bb44b71c62f54a3e1da2c11c73de5cf33766b8146c9c73f67711b9c07f0f1f6"
CASES = ("normal", "bad_nonce", "bad_tool", "missing_auth", "bad_signature", "wrong_key", "wrong_session",
         "wrong_challenge", "wrong_request", "wrong_broker", "wrong_root", "wrong_channel", "wrong_version",
         "wrong_phase", "stale", "replay", "final_bad_signature", "final_missing_auth", "final_execution_claim",
         "missing_trust", "revoked_trust", "incorrect_trust_key", "expired_trust", "broker_crash", "outage", "host_spoof")


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def package(root, trust):
    base = Path(sys.base_prefix); rt = root / "runtime"; rt.mkdir()
    for n in ("python.exe", "python312.dll", "python3.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        shutil.copy2(base / n, rt / n)
    with zipfile.ZipFile(rt / "python312.zip", "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in (base / "Lib").rglob("*.py"):
            if "site-packages" not in p.parts and "__pycache__" not in p.parts: z.write(p, p.relative_to(base / "Lib").as_posix())
    shutil.copytree(base / "DLLs", rt / "DLLs", ignore=shutil.ignore_patterns("*.pyc", "__pycache__"))
    # Reuse the already pinned Guardian cryptography dependency, not a new crypto implementation.
    dist = importlib.metadata.distribution("cryptography")
    if dist.version != "50.0.2": raise RuntimeError("CRYPTOGRAPHY_PIN_MISMATCH")
    shutil.copytree(Path(dist.locate_file("cryptography")), rt / "cryptography", ignore=shutil.ignore_patterns("*.pyc", "__pycache__"))
    if importlib.metadata.version("cffi") != "2.1.1": raise RuntimeError("CFFI_PIN_MISMATCH")
    backend = Path(importlib.util.find_spec("_cffi_backend").origin)
    shutil.copy2(backend, rt / backend.name)
    for rel in ("research/__init__.py", "research/auth_gateway_v1/__init__.py", "research/auth_gateway_v1/canonical.py", "research/auth_gateway_v1/errors.py"):
        dest = rt / rel; dest.parent.mkdir(parents=True, exist_ok=True)
        if not rel.endswith("__init__.py"): shutil.copy2(ROOT / rel, dest)
        else: dest.write_bytes(b"")
    for src, name in [(OLD / "reference_core/agent.py", "agent.py"), (OLD / "appcontainer_client.py", "ipc_transport.py"),
                      (HERE / "client.py", "client.py"), (HERE / "protocol.py", "protocol.py")]: shutil.copy2(src, rt / name)
    (rt / "psutil.py").write_bytes(b"def __getattr__(name):\n raise RuntimeError('HOST_SENSORS_DISABLED')\n")
    (rt / "python312._pth").write_bytes(b"python312.zip\nDLLs\n.\n")
    (rt / "broker-trust.json").write_bytes(encode(trust))
    return rt


def execute_case(case, folder, key, trust, replay=None):
    from guardian.windows import Container, acl, low_label
    from research.resonance_guardian_v1 import broker_host as transport
    root = Path(tempfile.mkdtemp(prefix="guardian-lab-mutual-", dir=os.environ["TEMP"]))
    container = None; proc = None
    result = {"schema": "guardian.mutual-native-case.v1", "case": case, "status": "CONTROL_BROKEN",
              "production_ready": False, "grant_issued": False, "tool_executed": False, "trust": trust,
              "started_at": int(time.time())}
    try:
        configured = dict(trust)
        if case == "revoked_trust": configured["revoked"] = True
        if case == "expired_trust": configured["expires_at"] = int(time.time()) - 1
        if case == "incorrect_trust_key": configured["public_key"] = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        rt = package(root, configured)
        smoke = subprocess.run([str(rt / "python.exe"), "-I", "-B", "-c", "import protocol; import ipc_transport; print('CRYPTO_RUNTIME_IMPORTED')"],
                               capture_output=True, timeout=15)
        (folder / (case + "-runtime-smoke.stdout")).write_bytes(smoke.stdout)
        (folder / (case + "-runtime-smoke.stderr")).write_bytes(smoke.stderr)
        if smoke.returncode: raise RuntimeError("CRYPTO_RUNTIME_IMPORT_FAILED")
        if case == "missing_trust": (rt / "broker-trust.json").unlink()
        result["configured_trust"] = configured if case != "missing_trust" else None
        result["runtime_files"] = {p.relative_to(rt).as_posix(): sha(p) for p in sorted(rt.rglob("*")) if p.is_file()}
        container = Container("guardian-mutual-" + uuid.uuid4().hex[:12])
        for p in [root, rt, *rt.rglob("*")]: acl(root, p, container.principal, writable=False)
        low_label(root, root)
        channel = "guardian-resonance-" + secrets.token_hex(12)
        result["channel_id"] = channel
        result["expected_sid_sha256"] = hashlib.sha256(container.principal.encode()).hexdigest()
        ready = folder / (case + "-ready.txt"); broker_out = folder / (case + "-broker.json")
        trustfile = folder / (case + "-public-trust.json"); trustfile.write_bytes(encode(trust))
        if case not in ("outage", "missing_trust", "revoked_trust", "expired_trust"):
            args = [sys.executable, "-B", str(HERE / "lab_server.py"), "--channel", channel, "--sid", container.principal,
                    "--ready", str(ready), "--out", str(broker_out), "--trust", str(trustfile), "--case", case]
            proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    cwd=ROOT, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            secret = {"key": key.private_bytes_raw().hex()}
            if replay is not None: secret["replay"] = replay
            proc.stdin.write(encode(secret) + b"\n"); proc.stdin.close(); proc.stdin = None
            for _ in range(100):
                if ready.exists() or proc.poll() is not None: break
                time.sleep(.05)
            if not ready.exists(): raise RuntimeError("BROKER_NOT_READY")
        if case == "host_spoof":
            # Unconfined caller attempts the same valid HELLO; server must refuse OS identity.
            import ctypes as c
            open_pipe = transport.api(transport.k, "CreateFileW", transport.w.HANDLE, transport.w.LPCWSTR,
                                      transport.w.DWORD, transport.w.DWORD, transport.P, transport.w.DWORD,
                                      transport.w.DWORD, transport.w.HANDLE)
            h = open_pipe(os.path.join(r"\\.\pipe", channel), 0xc0000000, 0, None, 3, 0, None)
            transport.check(h != transport.INVALID, "HOST_CONNECT")
            try:
                from research.guardian_mutual_ipc_v1.broker import send, receive
                send(h, ClientSession(trust, channel, int(time.time())).hello)
                result["host_reply"] = receive(h)
            finally: transport.close(h)
        else:
            observed = container.launch([str(rt / "python.exe"), "-I", "-B", str(rt / "client.py"), channel,
                                         case if case in ("bad_nonce", "bad_tool") else "normal"], root, timeout=20)
            result["client_exit"] = observed["exit_code"]
            result["client_token"] = {k: observed["token"].get(k) for k in ("appcontainer", "appcontainer_sid", "capability_count", "integrity_sid", "elevated")}
        if proc:
            stdout, stderr = proc.communicate(timeout=5)
            result["broker_exit"] = proc.returncode
            (folder / (case + "-broker.stdout")).write_bytes(stdout)
            (folder / (case + "-broker.stderr")).write_bytes(stderr)
            if broker_out.exists(): result["broker"] = json.loads(broker_out.read_bytes())
        result["status"] = "OBSERVED"
    except Exception as e:
        result.update(error=type(e).__name__, reason=str(e)[:180])
    finally:
        if proc and proc.poll() is None: proc.kill(); proc.communicate(timeout=5)
        if container: container.close()
        shutil.rmtree(root, ignore_errors=True)
        result["temporary_root_deleted"] = not root.exists()
        result["global_runtime_acl_changed"] = False
        result["finished_at"] = int(time.time())
        (folder / (case + ".json")).write_bytes(encode(result) + b"\n")
    return result


def main():
    p = argparse.ArgumentParser(); p.add_argument("--out", type=Path, required=True); p.add_argument("--case", choices=CASES)
    a = p.parse_args()
    if a.out.exists(): raise RuntimeError("OUTPUT_EXISTS")
    a.out.mkdir(parents=True)
    if os.name != "nt": raise RuntimeError("NOT_WINDOWS")
    if sha(OLD / "reference_core/agent.py") != CORE_SHA: raise RuntimeError("CORE_DRIFT")
    subprocess.run(["git", "merge-base", "--is-ancestor", BASE, "HEAD"], cwd=ROOT, check=True)
    key = Ed25519PrivateKey.generate(); now = int(time.time())
    trust = {"schema": "guardian.broker-trust.v1", "broker_id": "guardian-lab", "trust_root_version": "lab-root-v1",
             "key_id": "lab-ed25519", "public_key": key.public_key().public_bytes_raw().hex(), "revoked": False,
             "not_before": now - 5, "expires_at": now + 1800}
    (a.out / "trust.json").write_bytes(encode(trust))
    rows = []; replay = None
    for case in ([a.case] if a.case else CASES):
        r = execute_case(case, a.out, key, trust, replay)
        if case == "normal" and r.get("broker", {}).get("transcript"): replay = r["broker"]["transcript"][0]["reply"]
        rows.append({"case": case, "status": r["status"], "client_exit": r.get("client_exit"), "error": r.get("reason")})
        print(json.dumps(rows[-1]), flush=True)
    (a.out / "observations.json").write_bytes(encode(rows) + b"\n")
    return 0 if all(r["status"] == "OBSERVED" for r in rows) else 2


if __name__ == "__main__": raise SystemExit(main())
