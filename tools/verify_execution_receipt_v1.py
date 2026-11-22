"""Read-only execution receipt recomputation from explicit local artifacts."""

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from research.replay_challenge_v1.receipt import verify_execution_evidence


def _json(path):
    return json.loads(Path(path).read_text(encoding="ascii"))


def _public(path):
    value = serialization.load_pem_public_key(Path(path).read_bytes())
    if value.__class__.__name__ != "Ed25519PublicKey":
        raise ValueError("Ed25519 public key required")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--grant", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--grant-public-key", required=True, type=Path)
    parser.add_argument("--receipt-public-key", required=True, type=Path)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--worker-sha256", required=True)
    parser.add_argument("--image-identity", required=True)
    parser.add_argument("--trust-version", required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_execution_evidence(
            _json(args.request),
            _json(args.grant),
            _json(args.receipt),
            _public(args.grant_public_key),
            _public(args.receipt_public_key),
            args.scope,
            args.worker_sha256,
            args.image_identity,
            args.trust_version,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        result = {
            "classification": "UNVERIFIABLE",
            "verified": False,
            "reason": type(error).__name__,
        }
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(raw, encoding="ascii", newline="\n")
    print(raw, end="")
    return 0 if result.get("verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
