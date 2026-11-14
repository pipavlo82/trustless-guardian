"""SID-authenticated broker with signed replies; HOLD-only and no worker interface."""
import ctypes as c
import hashlib
import os
from pathlib import Path
import secrets
import time

from research.resonance_guardian_v1 import broker_host as win
from research.guardian_mutual_ipc_v1.protocol import (
    CONTEXT_FIELDS, Refused, decode, encode, require, sign_response, validate_hello, validate_trust,
)


def receive(pipe):
    buf = c.create_string_buffer(8192); n = win.w.DWORD()
    win.check(win.read_pipe(pipe, buf, 8192, c.byref(n), None), "ReadFile")
    return decode(buf.raw[:n.value])


def send(pipe, value):
    raw = encode(value)
    require(len(raw) <= 4096, "FRAME_SIZE")
    buf = c.create_string_buffer(raw); n = win.w.DWORD()
    win.check(win.write_pipe(pipe, buf, len(raw), c.byref(n), None), "WriteFile")
    require(n.value == len(raw), "SHORT_WRITE")


def serve(channel, app_sid, ready, out, trust, signing_key):
    validate_trust(trust, int(time.time()))
    require(win.re.fullmatch(r"guardian-resonance-[0-9a-f]{24}", channel), "CHANNEL")
    require(win.re.fullmatch(r"S-1-15-2-(?:[0-9]+-){6}[0-9]+", app_sid), "CLIENT_SID")
    owner = win.token_info()["user_sid"]
    sddl = "D:P(A;;GA;;;SY)(A;;GA;;;" + owner + ")(A;;GRGW;;;" + app_sid + ")S:(ML;;NW;;;LW)"
    sd = win.P(); win.check(win.convert(sddl, 1, c.byref(sd), None), "ConvertSDDL")
    attr = win.SECURITY_ATTRIBUTES(c.sizeof(win.SECURITY_ATTRIBUTES), sd, False)
    pipe = None
    result = {"schema": "guardian.mutual-broker-evidence.v1", "grant_issued": False,
              "tool_executed": False, "production_ready": False, "transcript": [], "verdict": "CONTROL_BROKEN"}
    try:
        # First pipe instance, message mode, local clients only. Original SID/owner ACL unchanged.
        pipe = win.create_pipe(os.path.join(r"\\.\pipe", channel), 3 | 0x80000, 6 | 8, 1, 4096, 4096, 5000, c.byref(attr))
        win.check(pipe and pipe != win.INVALID, "CreateNamedPipe")
        Path(ready).write_bytes(b"READY\n")
        if not win.connect_pipe(pipe, None):
            require(c.get_last_error() == 535, "CONNECT")
        hello = receive(pipe)
        ident = win.client_identity(pipe)
        result["client_identity"] = {"appcontainer": ident["appcontainer"], "capability_count": ident["capability_count"],
                                     "sid_sha256": hashlib.sha256(ident["sid"].encode()).hexdigest()}
        if not ident["appcontainer"] or ident["capability_count"] != 0 or ident["sid"] != app_sid:
            result["verdict"] = "DENY_CLIENT_IDENTITY"
            send(pipe, {"verdict": "DENY_CLIENT_IDENTITY"})
            return result
        validate_hello(hello, trust, channel)
        nonce = secrets.token_hex(32)
        response = {"verdict": "SYNTHETIC_OBSERVATIONS", "nonce": nonce, "observations_scaled": [20, 30, 40], "scale": 100, "tools_enabled": False}
        signed = sign_response(signing_key, hello, "hello", hello, response, int(time.time()))
        result["transcript"].append({"request": hello, "reply": signed})
        send(pipe, signed)
        proposal = receive(pipe)
        if proposal.get("op") == "CLIENT_RESULT":
            result.update(verdict="CLIENT_REFUSED", client_result=proposal)
            return result
        require(win.client_identity(pipe) == ident, "CLIENT_IDENTITY_CHANGED")
        expected = {**{k: hello[k] for k in CONTEXT_FIELDS}, "op": "PROPOSE_TOOL", "nonce": nonce,
                    "agent_id": "resonance-agent-v5", "tool": "resonance.synthetic-hash-only.v0",
                    "resource_id": "resonance-synthetic-observation-v0", "decision": "OBSERVE", "ticks": 3,
                    "docker_errors": {"linux": 5, "legacy": 5}}
        verdict = "HOLD_GUARDIAN_GRANT_REQUIRED" if proposal == expected else "DENY_REQUEST_OR_NONCE"
        response = {"verdict": verdict, "grant_issued": False, "tool_executed": False}
        signed = sign_response(signing_key, hello, "result", proposal, response, int(time.time()))
        result["transcript"].append({"request": proposal, "reply": signed})
        send(pipe, signed)
        result.update(verdict=verdict, client_result=receive(pipe))
        return result
    except (OSError, ValueError, RuntimeError) as e:
        result.update(error=type(e).__name__, reason=str(e)[:120])
        return result
    finally:
        if pipe and pipe != win.INVALID:
            win.disconnect(pipe); win.close(pipe)
        win.free_local(sd)
        Path(out).write_bytes(encode(result) + b"\n")
