"""Locally controlled trust-root and ownership-registry records."""

from dataclasses import dataclass, field

from .errors import SecurityError


@dataclass(frozen=True)
class JwtKeyRecord:
    kid: str
    algorithm: str
    public_key_pem: bytes
    not_before: int
    expires_at: int
    revoked: bool = False


@dataclass(frozen=True)
class WalletRecord:
    address: str
    subject: str
    roles: frozenset
    agent_ids: frozenset
    resource_ids: frozenset
    expires_at: int
    revoked: bool = False


@dataclass(frozen=True)
class McpTokenRecord:
    token_sha256: str
    token_id: str
    subject: str
    scopes: frozenset
    agent_id: str
    resource_id: str
    tool: str
    destination: str
    service: str
    not_before: int
    expires_at: int
    revoked: bool = False


@dataclass
class TrustRoot:
    version: str
    issuer: str
    audience: str
    observed_at: int
    max_staleness: int
    jwt_keys: dict = field(default_factory=dict)
    wallets: dict = field(default_factory=dict)
    mcp_tokens: dict = field(default_factory=dict)
    resource_owners: dict = field(default_factory=dict)
    agent_owners: dict = field(default_factory=dict)
    available: bool = True
    consistent: bool = True

    def validate(self, now):
        if not self.available:
            raise SecurityError("TRUST_ROOT_UNAVAILABLE")
        if not self.consistent:
            raise SecurityError("TRUST_ROOT_INCONSISTENT")
        if type(self.version) is not str or not self.version:
            raise SecurityError("TRUST_ROOT_VERSION")
        if type(now) not in {int, float}:
            raise TypeError("now")
        if self.observed_at > now + 5:
            raise SecurityError("TRUST_ROOT_FUTURE")
        if now - self.observed_at > self.max_staleness:
            raise SecurityError("TRUST_ROOT_STALE")
        if not self.jwt_keys or not self.wallets or not self.mcp_tokens:
            raise SecurityError("TRUST_ROOT_EMPTY")

    def active_key(self, kid, algorithm, now):
        self.validate(now)
        record = self.jwt_keys.get(kid)
        if record is None:
            raise SecurityError("JWT_KEY_UNKNOWN")
        if record.algorithm != algorithm:
            raise SecurityError("JWT_KEY_ALGORITHM")
        if record.revoked:
            raise SecurityError("JWT_KEY_REVOKED")
        if now < record.not_before:
            raise SecurityError("JWT_KEY_NOT_YET_VALID")
        if now >= record.expires_at:
            raise SecurityError("JWT_KEY_EXPIRED")
        return record

    def active_wallet(self, address, now):
        self.validate(now)
        record = self.wallets.get(address.lower())
        if record is None:
            raise SecurityError("WALLET_UNREGISTERED")
        if record.revoked:
            raise SecurityError("WALLET_REVOKED")
        if now >= record.expires_at:
            raise SecurityError("WALLET_REGISTRY_EXPIRED")
        return record
