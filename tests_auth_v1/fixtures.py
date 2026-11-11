"""Disposable local keys and registries; no fixture secret is committed."""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import secrets
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from eth_account import Account
from eth_account.messages import encode_defunct
import jwt
from siwe import SiweMessage

from research.auth_gateway_v1.grant import generate_grant_key
from research.auth_gateway_v1.model import RequestBinding
from research.auth_gateway_v1.nonce import BoundedNonceStore
from research.auth_gateway_v1.siwe_auth import expected_resources
from research.auth_gateway_v1.trust import (
    JwtKeyRecord,
    McpTokenRecord,
    TrustRoot,
    WalletRecord,
)


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _private_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _public_pem(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _rfc3339(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return value


class Fixture:
    def __init__(self, body=None):
        self.now = int(time.time())
        self.owner = Account.create()
        self.other_wallet = Account.create()
        self.key1 = _rsa_key()
        self.key2 = _rsa_key()
        self.wrong_key = _rsa_key()
        self.mcp_token = secrets.token_urlsafe(32)
        self.request = {
            "schema": "guardian.authenticated-request.v1",
            "request_id": "req-" + secrets.token_hex(8),
            "operation": "RUN_TOOL",
            "agent_id": "agent-local-1",
            "resource_id": "resource-local-1",
            "tool": "recompute",
            "destination": "mcp://local/recompute",
            "service": "MCP",
            "body": {"input": "local-fixture", "value": 7} if body is None else body,
        }
        self.binding = RequestBinding.from_request(self.request)
        wallet = WalletRecord(
            address=self.owner.address,
            subject="owner-local",
            roles=frozenset({"OWNER"}),
            agent_ids=frozenset({self.binding.agent_id}),
            resource_ids=frozenset({self.binding.resource_id}),
            expires_at=self.now + 3600,
        )
        token_hash = hashlib.sha256(self.mcp_token.encode("utf-8")).hexdigest()
        mcp = McpTokenRecord(
            token_sha256=token_hash,
            token_id="mcp-local-1",
            subject=wallet.subject,
            scopes=frozenset({"mcp:invoke", "tool:recompute"}),
            agent_id=self.binding.agent_id,
            resource_id=self.binding.resource_id,
            tool=self.binding.tool,
            destination=self.binding.destination,
            service=self.binding.service,
            not_before=self.now - 60,
            expires_at=self.now + 3600,
        )
        self.trust = TrustRoot(
            version="local-registry-v1",
            issuer="https://issuer.guardian.local",
            audience="guardian-gateway-local",
            observed_at=self.now,
            max_staleness=300,
            jwt_keys={
                "key-1": JwtKeyRecord("key-1", "RS256", _public_pem(self.key1), self.now - 60, self.now + 3600),
                "key-2": JwtKeyRecord("key-2", "RS256", _public_pem(self.key2), self.now - 60, self.now + 3600),
            },
            wallets={wallet.address.lower(): wallet},
            mcp_tokens={token_hash: mcp},
            resource_owners={self.binding.resource_id: wallet.subject},
            agent_owners={self.binding.agent_id: wallet.subject},
        )
        self.jwt_nonces = BoundedNonceStore(capacity=64, ttl_seconds=600)
        self.siwe_nonces = BoundedNonceStore(capacity=64, ttl_seconds=600)
        self.grant_nonces = BoundedNonceStore(capacity=64, ttl_seconds=600)
        self.grant_key = generate_grant_key()

    def jwt_claims(self, **overrides):
        claims = {
            "iss": self.trust.issuer,
            "aud": self.trust.audience,
            "exp": self.now + 180,
            "nbf": self.now - 1,
            "iat": self.now - 1,
            "sub": "owner-local",
            "jti": "jwt-" + secrets.token_hex(8),
            "role": "OWNER",
            "wallet": self.owner.address,
            "agent_id": self.binding.agent_id,
            "resource_id": self.binding.resource_id,
            "tool": self.binding.tool,
            "destination": self.binding.destination,
            "service": self.binding.service,
            "request_id": self.binding.request_id,
            "body_sha256": self.binding.body_sha256,
        }
        claims.update(overrides)
        return claims

    def make_jwt(self, key=None, kid="key-1", algorithm="RS256", headers=None, **overrides):
        key = self.key1 if key is None else key
        header = {"kid": kid, "typ": "JWT"}
        if headers:
            header.update(headers)
        return jwt.encode(
            self.jwt_claims(**overrides),
            _private_pem(key),
            algorithm=algorithm,
            headers=header,
        )

    def make_siwe(self, account=None, nonce=None, **overrides):
        account = self.owner if account is None else account
        nonce = secrets.token_hex(8) if nonce is None else nonce
        issued = datetime.fromtimestamp(self.now - 1, timezone.utc)
        values = {
            "scheme": "https",
            "domain": "guardian.local",
            "address": account.address,
            "uri": "https://guardian.local/auth",
            "version": "1",
            "chain_id": 31337,
            "issued_at": issued,
            "nonce": nonce,
            "statement": "Authorize one confined Guardian request",
            "expiration_time": datetime.fromtimestamp(self.now + 180, timezone.utc),
            "not_before": issued,
            "request_id": self.binding.request_id,
            "resources": list(expected_resources(self.binding)),
        }
        values.update(overrides)
        for name in ("issued_at", "expiration_time", "not_before"):
            values[name] = _rfc3339(values[name])
        message = SiweMessage(**values)
        prepared = message.prepare_message()
        signature = Account.sign_message(
            encode_defunct(text=prepared),
            private_key=account.key,
        ).signature.to_0x_hex()
        return prepared, signature

    def mcp_header(self):
        return "Bearer " + self.mcp_token

    def replace_wallet(self, **changes):
        current = next(iter(self.trust.wallets.values()))
        updated = replace(current, **changes)
        self.trust.wallets = {updated.address.lower(): updated}
        return updated

    def replace_mcp(self, **changes):
        digest, current = next(iter(self.trust.mcp_tokens.items()))
        self.trust.mcp_tokens = {digest: replace(current, **changes)}
