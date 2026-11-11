"""Strict RS256 JWT authentication with registry and request binding."""

import base64

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .errors import SecurityError
from .model import AuthenticatedPrincipal


PINNED_ALGORITHM = "RS256"
ALLOWED_ROLES = frozenset({"ADMIN", "OWNER", "SERVICE"})
REQUIRED_CLAIMS = frozenset(
    {
        "iss",
        "aud",
        "exp",
        "nbf",
        "iat",
        "sub",
        "jti",
        "role",
        "wallet",
        "agent_id",
        "resource_id",
        "tool",
        "destination",
        "service",
        "request_id",
        "body_sha256",
    }
)


def _independent_rs256_verify(token, public_key_pem):
    try:
        header, payload, encoded_signature = token.split(".")
        signature = base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4))
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(
            signature,
            (header + "." + payload).encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (ValueError, TypeError, UnicodeError, InvalidSignature) as error:
        raise SecurityError("JWT_INDEPENDENT_SIGNATURE") from error


def authenticate_jwt(token, binding, trust, nonce_store, now):
    trust.validate(now)
    if type(token) is not str or not token or len(token) > 16384:
        raise SecurityError("JWT_FORMAT")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as error:
        raise SecurityError("JWT_HEADER") from error
    if type(header) is not dict or set(header) != {"alg", "kid", "typ"}:
        raise SecurityError("JWT_HEADER_SHAPE")
    if header["alg"] != PINNED_ALGORITHM:
        raise SecurityError("JWT_ALGORITHM")
    if header["typ"] != "JWT":
        raise SecurityError("JWT_TYPE")
    if type(header["kid"]) is not str or not header["kid"]:
        raise SecurityError("JWT_KID")
    record = trust.active_key(header["kid"], PINNED_ALGORITHM, now)
    try:
        claims = jwt.decode(
            token,
            record.public_key_pem,
            algorithms=[PINNED_ALGORITHM],
            audience=trust.audience,
            issuer=trust.issuer,
            leeway=0,
            options={
                "require": sorted(REQUIRED_CLAIMS),
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_sub": True,
                "strict_aud": True,
            },
        )
    except jwt.PyJWTError as error:
        raise SecurityError("JWT_CRYPTO_OR_CLAIMS") from error
    _independent_rs256_verify(token, record.public_key_pem)
    if type(claims) is not dict or set(claims) != REQUIRED_CLAIMS:
        raise SecurityError("JWT_CLAIMS_SHAPE")
    string_claims = REQUIRED_CLAIMS - {"exp", "nbf", "iat"}
    for name in string_claims:
        if type(claims[name]) is not str or not claims[name]:
            raise SecurityError("JWT_CLAIM_TYPE")
    for name in ("exp", "nbf", "iat"):
        if type(claims[name]) is not int:
            raise SecurityError("JWT_TIME_TYPE")
    if claims["aud"] != trust.audience or claims["iss"] != trust.issuer:
        raise SecurityError("JWT_TRUST_DOMAIN")
    if claims["role"] not in ALLOWED_ROLES:
        raise SecurityError("JWT_ROLE")
    if claims["iat"] > now or claims["nbf"] > now:
        raise SecurityError("JWT_NOT_YET_VALID")
    if claims["exp"] <= now or claims["exp"] - claims["iat"] > 300:
        raise SecurityError("JWT_LIFETIME")
    if claims["exp"] > record.expires_at:
        raise SecurityError("JWT_OUTLIVES_KEY")
    expected = binding.as_dict()
    for name in ("agent_id", "resource_id", "tool", "destination", "service", "request_id", "body_sha256"):
        if claims[name] != expected[name]:
            raise SecurityError("JWT_REQUEST_BINDING")
    wallet = trust.active_wallet(claims["wallet"], now)
    if wallet.subject != claims["sub"]:
        raise SecurityError("JWT_WALLET_SUBJECT")
    if claims["role"] not in wallet.roles:
        raise SecurityError("JWT_WALLET_ROLE")
    if binding.agent_id not in wallet.agent_ids or binding.resource_id not in wallet.resource_ids:
        raise SecurityError("JWT_WALLET_RESOURCE")
    nonce_store.consume(
        "jwt:" + claims["iss"] + ":" + claims["sub"],
        claims["jti"],
        now,
        expires_at=claims["exp"],
    )
    return AuthenticatedPrincipal(
        subject=claims["sub"],
        role=claims["role"],
        wallet=claims["wallet"].lower(),
        source="JWT_RS256",
        token_id=claims["jti"],
        key_id=record.kid,
    )
