"""Subprocess admission probe for restart and inter-process atomicity tests."""

import argparse
import base64
import json
from pathlib import Path
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from research.auth_gateway_v1.canonical import canonical_json_bytes
from research.auth_gateway_v1.errors import SecurityError
from research.auth_gateway_v1.model import RequestBinding
from research.replay_challenge_v1.durable import DurableSecurityState
from research.replay_challenge_v1.scoped_grant import verify_scoped_execution_grant


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--mode", choices=("execute", "claim-only"), default="execute")
    parser.add_argument("--delay", type=float, default=0.0)
    args = parser.parse_args(argv)
    data = json.loads(Path(args.state).read_text(encoding="ascii"))
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(data["public_key"]))
    binding = RequestBinding.from_request(data["request"])
    durable = DurableSecurityState(args.db, args.scope)
    try:
        payload, digest = verify_scoped_execution_grant(
            data["grant"],
            public_key,
            data["now"],
            args.scope,
            binding,
            data["worker_sha256"],
            data["image_identity"],
            data["trust_version"],
        )
        claim = durable.prepare_admission(
            payload["grant_id"],
            digest,
            payload["binding_sha256"],
            args.session,
            "process-attempt-" + args.session,
            data["now"],
            payload["expires_at"],
        )
        if args.mode == "claim-only":
            status = "PREPARED"
        else:
            if args.delay:
                time.sleep(args.delay)
            outcome_sha256 = __import__("hashlib").sha256(
                canonical_json_bytes({"process": args.session, "result": "observed"})
            ).hexdigest()
            durable.mark_committed(claim, data["now"], outcome_sha256, 0)
            status = "EXECUTED"
        result = {"status": status}
    except SecurityError as error:
        result = {"status": "REFUSED", "reason": error.code}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
