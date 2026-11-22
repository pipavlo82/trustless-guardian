"""EIP-4361 parsing plus independent EIP-191 address recovery."""

from datetime import datetime, timezone

from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import ValidationError
from siwe import SiweMessage, VerificationError

from .errors import SecurityError
from .model import AuthenticatedPrincipal


def expected_resources(binding):
    return (
        "urn:guardian:agent:" + binding.agent_id,
        "urn:guardian:resource:" + binding.resource_id,
        "urn:guardian:tool:" + binding.tool,
        "urn:guardian:destination:" + binding.destination,
        "urn:guardian:service:" + binding.service,
        "urn:guardian:body-sha256:" + binding.body_sha256,
    )


def _timestamp(value):
    return int(value._datetime.timestamp())


def authenticate_siwe(
    message,
    signature,
    binding,
    trust,
    nonce_store,
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
    try:
        parsed.verify(
            signature,
            scheme="https",
            domain=expected_domain,
            nonce=parsed.nonce,
            timestamp=datetime.fromtimestamp(now, timezone.utc),
        )
    except VerificationError as error:
        raise SecurityError("SIWE_CRYPTO_OR_TIME") from error
    if parsed.version.value != "1" or parsed.chain_id != expected_chain_id:
        raise SecurityError("SIWE_DOMAIN_BINDING")
    if str(parsed.uri) != expected_uri or parsed.request_id != binding.request_id:
        raise SecurityError("SIWE_REQUEST_BINDING")
    if parsed.statement != "Authorize one confined Guardian request":
        raise SecurityError("SIWE_STATEMENT")
    if parsed.expiration_time is None or parsed.not_before is None:
        raise SecurityError("SIWE_TIME_REQUIRED")
    issued_at = _timestamp(parsed.issued_at)
    not_before = _timestamp(parsed.not_before)
    expires_at = _timestamp(parsed.expiration_time)
    if issued_at > now or not_before > now or expires_at <= now:
        raise SecurityError("SIWE_TIME")
    if expires_at - issued_at > 300 or not_before < issued_at:
        raise SecurityError("SIWE_LIFETIME")
    resources = tuple(str(resource) for resource in (parsed.resources or []))
    if resources != expected_resources(binding):
        raise SecurityError("SIWE_RESOURCE_BINDING")
    try:
        recovered = Account.recover_message(
            encode_defunct(text=parsed.prepare_message()),
            signature=signature,
        )
    except (ValueError, TypeError, IndexError) as error:
        raise SecurityError("SIWE_INDEPENDENT_RECOVERY") from error
    if recovered.lower() != parsed.address.lower():
        raise SecurityError("SIWE_RECOVERY_MISMATCH")
    wallet = trust.active_wallet(parsed.address, now)
    if wallet.address.lower() != recovered.lower():
        raise SecurityError("SIWE_WALLET_REGISTRY")
    if binding.agent_id not in wallet.agent_ids or binding.resource_id not in wallet.resource_ids:
        raise SecurityError("SIWE_WALLET_RESOURCE")
    if len(wallet.roles) != 1:
        raise SecurityError("SIWE_ROLE_AMBIGUOUS")
    role = next(iter(wallet.roles))
    nonce_store.consume(
        "siwe:" + expected_domain + ":" + wallet.subject,
        parsed.nonce,
        now,
        expires_at=expires_at,
    )
    return AuthenticatedPrincipal(
        subject=wallet.subject,
        role=role,
        wallet=wallet.address.lower(),
        source="SIWE_EIP4361_EIP191",
        token_id=parsed.nonce,
        key_id="wallet:" + wallet.address.lower(),
    )
