"""Runs in read-only private Python runtime, zero-capability AppContainer."""
import json
from pathlib import Path
import sys
import time

import agent  # unchanged original reference core
import ipc_transport as wire  # byte-for-byte PR7 transport copy
from protocol import ClientSession, Refused, decode, encode, require


def send(handle, value):
    raw = encode(value)
    require(len(raw) <= 4096, "FRAME_SIZE")
    b = wire.c.create_string_buffer(raw); n = wire.w.DWORD()
    if not wire.WriteFile(handle, b, len(raw), wire.c.byref(n), None) or n.value != len(raw):
        raise OSError("IPC_WRITE")


def receive(handle):
    b = wire.c.create_string_buffer(8192); n = wire.w.DWORD()
    if not wire.ReadFile(handle, b, 8192, wire.c.byref(n), None):
        raise OSError("IPC_READ")
    return decode(b.raw[:n.value])


def run(channel, mode):
    handle = None
    try:
        # No root/key is accepted from the broker. Only launcher-provisioned read-only public trust.
        trust = decode(Path(__file__).with_name("broker-trust.json").read_bytes())
        session = ClientSession(trust, channel, int(time.time()))
    except (Refused, OSError, ValueError):
        return 89
    try:
        docker = {"linux": wire.direct_pipe_error("linux"), "legacy": wire.direct_pipe_error("legacy")}
        require(docker == {"linux": 5, "legacy": 5}, "CONFINEMENT")
        handle = wire.pipe_open(channel)
        send(handle, session.hello)
        answer = session.accept(receive(handle), "hello", session.hello, int(time.time()))
        s = agent.State()
        for v in answer["observations_scaled"]:
            s, d = agent.decide(s, {k: v / answer["scale"] for k in agent.FIELDS})
        require(s.step == 3 and d["action"] == "OBSERVE", "CORE")
        proposal = {**session.context, "op": "PROPOSE_TOOL", "nonce": answer["nonce"],
                    "agent_id": "resonance-agent-v5", "tool": "resonance.synthetic-hash-only.v0",
                    "resource_id": "resonance-synthetic-observation-v0", "decision": d["action"],
                    "ticks": s.step, "docker_errors": docker}
        if mode == "bad_nonce": proposal["nonce"] = "0" * 64
        if mode == "bad_tool": proposal["tool"] = "shell"
        require(mode in ("normal", "bad_nonce", "bad_tool"), "MODE")
        send(handle, proposal)
        reply = session.accept(receive(handle), "result", proposal, int(time.time()))
        code = 73 if reply["verdict"] == "HOLD_GUARDIAN_GRANT_REQUIRED" else 75
        send(handle, {"op": "CLIENT_RESULT", "code": code, "reason": reply["verdict"]})
        return code
    except Refused as e:
        if handle:
            try: send(handle, {"op": "CLIENT_RESULT", "code": 88, "reason": e.code})
            except OSError: pass
        return 88
    except OSError:
        return 86 if handle is None else 87
    finally:
        if handle: wire.CloseHandle(handle)


if __name__ == "__main__":
    try: sys.exit(run(sys.argv[1], sys.argv[2]))
    except Exception: sys.exit(99)  # harness/runtime failure, never an authenticated negative PASS
