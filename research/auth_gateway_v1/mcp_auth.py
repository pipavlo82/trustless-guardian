"""Opaque MCP bearer authentication with exact scoped binding."""

import hashlib
import hmac

from .errors import SecurityError
from .model import McpPrincipal


def authenticate_mcp(header, binding, trust, expected_subject, now):
    trust.validate(now)
    if type(header) is not str or not header.startswith("Bearer "):
        raise SecurityError("MCP_BEARER_FORMAT")
    token = header[7:]
    if not token or token.strip() != token or " " in token or len(token) > 1024:
        raise SecurityError("MCP_BEARER_FORMAT")
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    record = trust.mcp_tokens.get(digest)
    if record is None or not hmac.compare_digest(record.token_sha256, digest):
        raise SecurityError("MCP_BEARER_UNKNOWN")
    if record.revoked:
        raise SecurityError("MCP_BEARER_REVOKED")
    if now < record.not_before or now >= record.expires_at:
        raise SecurityError("MCP_BEARER_TIME")
    if record.subject != expected_subject:
        raise SecurityError("MCP_SUBJECT")
    if "mcp:invoke" not in record.scopes or "tool:" + binding.tool not in record.scopes:
        raise SecurityError("MCP_SCOPE")
    exact = (
        record.agent_id == binding.agent_id
        and record.resource_id == binding.resource_id
        and record.tool == binding.tool
        and record.destination == binding.destination
        and record.service == binding.service
    )
    if not exact:
        raise SecurityError("MCP_REQUEST_BINDING")
    return McpPrincipal(record.subject, record.scopes, record.token_id)
