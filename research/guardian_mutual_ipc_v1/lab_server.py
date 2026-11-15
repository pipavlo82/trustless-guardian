"""Synthetic negative broker fixture. Never used by the agent or an execution service."""
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.guardian_mutual_ipc_v1 import broker
from research.guardian_mutual_ipc_v1.protocol import DOMAIN, encode


def main():
    p = argparse.ArgumentParser()
    for name in ("channel", "sid", "ready", "out", "trust", "case"): p.add_argument("--" + name, required=True)
    args = p.parse_args()
    # Fresh disposable lab key via anonymous stdin, never arguments, environment, agent or evidence.
    secret = json.loads(sys.stdin.buffer.readline(4096))
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret["key"]))
    trust = json.loads(Path(args.trust).read_bytes())
    original = broker.sign_response
    def altered(key_arg, context, phase, request, response, now):
        if args.case == "broker_crash": raise OSError("SYNTHETIC_BROKER_CRASH")
        if (args.case,phase) in (('silent_hello','hello'),('silent_result','result')): time.sleep(6)
        out = original(key_arg, context, phase, request, response, now)
        if phase != ("result" if args.case.startswith("final_") else "hello"): return out
        case = args.case.removeprefix("final_")
        if case == "missing_auth": return response
        if case == "bad_signature": out["signature"] = "00" * 64; return out
        if case == "wrong_key":
            out["signature"] = Ed25519PrivateKey.generate().sign(DOMAIN + encode(out["payload"])).hex(); return out
        if case == "replay": return secret["replay"]
        changes = {"wrong_session": ("session_id", "0" * 64), "wrong_challenge": ("client_challenge", "0" * 64),
                   "wrong_request": ("request_sha256", "0" * 64), "wrong_broker": ("broker_id", "substituted-broker"),
                   "wrong_root": ("trust_root_version", "untrusted-version"), "wrong_channel": ("channel_id", "guardian-resonance-" + "0" * 24),
                   "wrong_version": ("protocol", "guardian.mutual-ipc-auth.v0"), "wrong_phase": ("phase", "result")}
        if case in changes:
            field, value = changes[case]; out["payload"][field] = value
        if case == "stale":
            out["payload"]["issued_at"] -= 60; out["payload"]["expires_at"] -= 60
        if case == "execution_claim": out["payload"]["response"]["tool_executed"] = True
        out["signature"] = key_arg.sign(DOMAIN + encode(out["payload"])).hex()
        return out
    broker.sign_response = altered
    result = broker.serve(args.channel, args.sid, args.ready, args.out, trust, key)
    print(json.dumps({"verdict": result["verdict"]}, sort_keys=True))
    return 0 if result["verdict"] != "CONTROL_BROKEN" else 3


if __name__ == "__main__": raise SystemExit(main())
