"""Disposable challenged-auth fixture helpers."""

from datetime import datetime, timezone

from eth_account import Account
from eth_account.messages import encode_defunct
from siwe import SiweMessage

from research.replay_challenge_v1.challenge import challenged_resources


def rfc3339(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def make_message(challenge, binding, account, **overrides):
    values = {
        "scheme": "https",
        "domain": challenge["domain"],
        "address": account.address,
        "uri": challenge["uri"],
        "version": "1",
        "chain_id": challenge["chain_id"],
        "issued_at": rfc3339(challenge["issued_at"]),
        "nonce": challenge["nonce"],
        "statement": "Authorize one confined Guardian request from a server challenge",
        "expiration_time": rfc3339(challenge["expires_at"]),
        "not_before": rfc3339(challenge["issued_at"]),
        "request_id": challenge["request_id"],
        "resources": list(challenged_resources(binding, challenge["challenge_id"], challenge["session_id"])),
    }
    values.update(overrides)
    message = SiweMessage(**values).prepare_message()
    signature = Account.sign_message(
        encode_defunct(text=message),
        private_key=account.key,
    ).signature.to_0x_hex()
    return message, signature
