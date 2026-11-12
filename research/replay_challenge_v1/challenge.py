"""Server-issued EIP-4361 challenges with durable single-use consumption."""

from datetime import datetime, timedelta, timezone
import hashlib

from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import ValidationError
from siwe import SiweMessage, VerificationError

from research.auth_gateway_v1.errors import SecurityError
from research.auth_gateway_v1.model import AuthenticatedPrincipal
from research.auth_gateway_v1.siwe_auth import expected_resources


def _rfc3339(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _timestamp(value):
    return int(value._datetime.timestamp())


def session_digest(session_id):
    if type(session_id) is not str or not session_id:
        raise SecurityError("SIWE_CHALLENGE_SESSION")
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def challenged_resources(binding, challenge_id, session_id):
    return expected_resources(binding) + (
        "urn:guardian:challenge:" + challenge_id,
        "urn:guardian:session-sha256:" + session_digest(session_id),
    )


def prepare_challenge_message(challenge, binding, account):
    if type(challenge) is not dict or challenge.get("schema") != "guardian.siwe-challenge.v1":
        raise SecurityError("SIWE_CHALLENGE_RECORD")
    if account.address.lower() != challenge["wallet"].lower():
        raise SecurityError("SIWE_CHALLENGE_WALLET")
    values = {
        "scheme": "https",
        "domain": challenge["domain"],
        "address": account.address,
        "uri": challenge["uri"],
        "version": "1",
        "chain_id": challenge["chain_id"],
        "issued_at": _rfc3339(challenge["issued_at"]),
        "nonce": challenge["nonce"],
        "statement": "Authorize one confined Guardian request from a server challenge",
        "expiration_time": _rfc3339(challenge["expires_at"]),
        "not_before": _rfc3339(challenge["issued_at"]),
        "request_id": challenge["request_id"],
        "resources": list(challenged_resources(binding, challenge["challenge_id"], challenge["session_id"])),
    }
    message = SiweMessage(**values).prepare_message()
    signature = Account.sign_message(
        encode_defunct(text=message),
        private_key=account.key,
    ).signature.to_0x_hex()
    return message, signature


def authenticate_challenged_siwe(
    message,
    signature,
    challenge_id,
    session_id,
    binding,
    expected_wallet,
    trust,
    durable_state,
    now,
    expected_domain="guardian.local",
    expected_uri="https://guardian.local/auth",
    expected_chain_id=31337,
):
    trust.validate(now)
    if type(message) is not str or not message or len(message) > 8192:
        raise SecurityError("SIWE_MESSAGE_FORMAT")
    if type(signature) is not str or not signature or len(signature) > 512:
        raise SecurityError("SIWE_SIGNATURE_FORMAT")
    try:
        parsed = SiweMessage.from_message(message, abnf=True)
    except (ValueError, TypeError, ValidationError) as error:
        raise SecurityError("SIWE_PARSE") from error
    record = durable_state.inspect_challenge(
        challenge_id,
        session_id,
        expected_domain,
        expected_uri,
        expected_wallet,
        expected_chain_id,
        binding.request_id,
        binding.digest(),
        now,
    )
    if (
        parsed.domain != record["domain"]
        or str(parsed.uri) != record["uri"]
        or parsed.address.lower() != record["wallet"]
        or parsed.chain_id != record["chain_id"]
        or parsed.request_id != record["request_id"]
        or parsed.nonce != record["nonce"]
    ):
        raise SecurityError("SIWE_CHALLENGE_MESSAGE_BINDING")
    if parsed.version.value != "1":
        raise SecurityError("SIWE_DOMAIN_BINDING")
    if parsed.statement != "Authorize one confined Guardian request from a server challenge":
        raise SecurityError("SIWE_STATEMENT")
    if parsed.expiration_time is None or parsed.not_before is None:
        raise SecurityError("SIWE_TIME_REQUIRED")
    issued_at = _timestamp(parsed.issued_at)
    not_before = _timestamp(parsed.not_before)
    expires_at = _timestamp(parsed.expiration_time)
    if (
        issued_at != record["issued_at"]
        or not_before != record["issued_at"]
        or expires_at != record["expires_at"]
    ):
        raise SecurityError("SIWE_CHALLENGE_TIME_BINDING")
    if issued_at > now or expires_at <= now or expires_at - issued_at > 300:
        raise SecurityError("SIWE_CHALLENGE_EXPIRED")
    resources = tuple(str(resource) for resource in (parsed.resources or []))
    if resources != challenged_resources(binding, challenge_id, session_id):
        raise SecurityError("SIWE_CHALLENGE_RESOURCE_BINDING")
    try:
        parsed.verify(
            signature,
            scheme="https",
            domain=record["domain"],
            nonce=record["nonce"],
            # siwe-py treats equality with not-before as not yet valid.  The
            # durable challenge uses integer-second timestamps, so advance by
            # the smallest representable amount after independently enforcing
            # issued_at <= now < expires_at above.
            timestamp=datetime.fromtimestamp(now, timezone.utc) + timedelta(microseconds=1),
        )
    except VerificationError as error:
        raise SecurityError("SIWE_CRYPTO_OR_TIME") from error
    try:
        recovered = Account.recover_message(
            encode_defunct(text=parsed.prepare_message()),
            signature=signature,
        )
    except (ValueError, TypeError, IndexError) as error:
        raise SecurityError("SIWE_INDEPENDENT_RECOVERY") from error
    if recovered.lower() != parsed.address.lower():
        raise SecurityError("SIWE_RECOVERY_MISMATCH")
    wallet = trust.active_wallet(recovered, now)
    if wallet.address.lower() != record["wallet"] or wallet.address.lower() != expected_wallet.lower():
        raise SecurityError("SIWE_WALLET_REGISTRY")
    if binding.agent_id not in wallet.agent_ids or binding.resource_id not in wallet.resource_ids:
        raise SecurityError("SIWE_WALLET_RESOURCE")
    if len(wallet.roles) != 1:
        raise SecurityError("SIWE_ROLE_AMBIGUOUS")
    durable_state.consume_challenge(record, now)
    return AuthenticatedPrincipal(
        subject=wallet.subject,
        role=next(iter(wallet.roles)),
        wallet=wallet.address.lower(),
        source="SIWE_EIP4361_SERVER_CHALLENGE_EIP191",
        token_id=challenge_id,
        key_id="wallet:" + wallet.address.lower(),
    )
