"""RC2 host adapter around the frozen Guardian scoped-execution laboratory.

This file creates no new authorization path.  The original native broker,
policy admission, v2 scoped grant, durable replay state, Docker executor and
signed receipt issuer remain the authority.  The adapter only binds an
out-of-band Core V2 intent digest to the authenticated AppContainer session and
therefore to the existing request/grant/receipt chain.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import time

GUARDIAN_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(GUARDIAN_ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.guardian_mutual_ipc_v1.broker import serve
from research.scoped_execution_lab_v3.unified_state import UnifiedState
from research.scoped_execution_lab_v3 import lab


def canonical(value) -> bytes:
    return lab.canonical(value)


def intent_canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def put(path: Path, value) -> None:
    path.write_bytes(canonical(value) + b"\n")


def main() -> int:
    # Recovery entrypoint uses the same gated authoritative reconciler; no new recovery algorithm.
    if len(sys.argv) == 3 and sys.argv[1] == '--recover':
        from research.scoped_execution_lab_v3.reconcile_v3_hardened import reconcile
        result = reconcile(Path(sys.argv[2]).resolve())
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get('status') == 'LOCAL_RECONCILED_EXTERNAL_HOLD' else 2
    parser = argparse.ArgumentParser()
    for name in ("channel", "sid", "ready", "out", "trust", "intent"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    out = Path(args.out).resolve()
    secret = json.loads(sys.stdin.buffer.readline(4096))
    broker_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret["key"]))
    trust = json.loads(Path(args.trust).read_bytes())
    intent_raw = Path(args.intent).read_bytes()
    intent = json.loads(intent_raw)
    if intent_raw != intent_canonical(intent) + b"\n":
        raise RuntimeError("RC2_INTENT_NONCANONICAL")
    intent_sha256 = sha(intent_canonical(intent))

    native = serve(args.channel, args.sid, args.ready, out / "broker.json", trust, broker_key)
    now = int(time.time())
    policy = {
        "schema": "guardian.synthetic-policy.v1",
        "enabled": True,
        "revoked": False,
        "sid": args.sid,
        "epoch": 1,
        "not_before": now - 1,
        "expires_at": now + 90,
    }
    put(out / "policy.json", policy)
    summary = {
        "schema": "resonance.rc2.guardian-execution-summary.v1",
        "intent_sha256": intent_sha256,
        "lab_grant_issued": False,
        "execution": {"status": "REFUSED", "reason": "RC2_NOT_ADMITTED", "launches": 0},
        "negative_controls": {},
    }
    state = None
    try:
        proposal = native.get("transcript", [{}, {"request": {}}])[1]["request"]
        lab.require(proposal.get("session_id") == intent_sha256, "RC2_INTENT_SESSION_BINDING")
        request = lab.admit_live_result(native, args.sid, policy, now)
        request["body"]["rc2_intent_sha256"] = intent_sha256
        request["body"]["rc2_decision_action"] = intent["decision"]["action"]
        request["body"]["rc2_telemetry_sha256"] = intent["telemetry"]["evidence_sha256"]
        grant_key = Ed25519PrivateKey.generate()
        receipt_key = Ed25519PrivateKey.generate()
        grant = lab.issue(request, grant_key, args.sid, now)
        state = UnifiedState(out / "state.sqlite", lab.SCOPE)
        executed = lab.execute(
            request, grant, grant_key.public_key(), receipt_key, state,
            policy, args.sid, now, out / "job",
        )
        replay = lab.execute(
            request, grant, grant_key.public_key(), receipt_key, state,
            policy, args.sid, now, out / "negative-grant-replay",
        )
        substituted = copy.deepcopy(request)
        substituted["body"]["rc2_decision_action"] = "SUBSTITUTED_AFTER_AUTH"
        substitution = lab.execute(
            substituted, grant, grant_key.public_key(), receipt_key, state,
            policy, args.sid, now, out / "negative-request-substitution",
        )
        missing_grant = lab.execute(
            request, {}, grant_key.public_key(), receipt_key, state,
            policy, args.sid, now, out / "negative-missing-grant",
        )
        revoked_policy = dict(policy)
        revoked_policy["revoked"] = True
        revoked = lab.execute(
            request, grant, grant_key.public_key(), receipt_key, state,
            revoked_policy, args.sid, now, out / "negative-revoked-policy",
        )
        summary.update(
            lab_grant_issued=True,
            execution=executed,
            negative_controls={
                "grant_replay": replay,
                "request_substitution_after_authorization": substitution,
                "missing_grant": missing_grant,
                "revoked_guardian_policy": revoked,
            },
            request_sha256=sha(canonical(request)),
        )
    except (lab.SecurityError, KeyError, IndexError, TypeError, ValueError) as error:
        summary["execution"] = {
            "status": "REFUSED",
            "reason": getattr(error, "code", type(error).__name__),
            "launches": 0,
        }
    finally:
        if state is not None:
            state.close()
    put(out / "execution.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
