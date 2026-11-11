"""Strict request and authenticated-principal models."""

from dataclasses import dataclass

from .canonical import canonical_json_bytes, sha256_hex
from .errors import SecurityError


REQUEST_FIELDS = frozenset(
    {
        "schema",
        "request_id",
        "operation",
        "agent_id",
        "resource_id",
        "tool",
        "destination",
        "service",
        "body",
    }
)


@dataclass(frozen=True)
class RequestBinding:
    request_id: str
    operation: str
    agent_id: str
    resource_id: str
    tool: str
    destination: str
    service: str
    body_sha256: str

    @classmethod
    def from_request(cls, request):
        if type(request) is not dict or set(request) != REQUEST_FIELDS:
            raise SecurityError("REQUEST_SCHEMA")
        if request["schema"] != "guardian.authenticated-request.v1":
            raise SecurityError("REQUEST_VERSION")
        names = (
            "request_id",
            "operation",
            "agent_id",
            "resource_id",
            "tool",
            "destination",
            "service",
        )
        for name in names:
            if type(request[name]) is not str or not request[name] or len(request[name]) > 256:
                raise SecurityError("REQUEST_FIELD")
        if type(request["body"]) is not dict:
            raise SecurityError("REQUEST_BODY")
        body_sha256 = sha256_hex(canonical_json_bytes(request["body"]))
        return cls(*(request[name] for name in names), body_sha256)

    def as_dict(self):
        return {
            "agent_id": self.agent_id,
            "body_sha256": self.body_sha256,
            "destination": self.destination,
            "operation": self.operation,
            "request_id": self.request_id,
            "resource_id": self.resource_id,
            "service": self.service,
            "tool": self.tool,
        }

    def digest(self):
        return sha256_hex(canonical_json_bytes(self.as_dict()))


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    subject: str
    role: str
    wallet: str
    source: str
    token_id: str
    key_id: str


@dataclass(frozen=True)
class McpPrincipal:
    subject: str
    scopes: frozenset
    token_id: str


@dataclass(frozen=True)
class AuthorizationDecision:
    verdict: str
    reason: str

    @property
    def allowed(self):
        return self.verdict == "ALLOW"
