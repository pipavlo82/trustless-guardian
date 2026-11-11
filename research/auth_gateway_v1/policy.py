"""Authorization is independent of authentication and anomaly detection."""

from .model import AuthorizationDecision


def authorize(jwt_principal, siwe_principal, mcp_principal, binding, trust, now):
    trust.validate(now)
    if (
        jwt_principal.subject != siwe_principal.subject
        or jwt_principal.role != siwe_principal.role
        or jwt_principal.wallet != siwe_principal.wallet
    ):
        return AuthorizationDecision("DENY", "AUTHENTICATOR_SUBSTITUTION")
    if mcp_principal.subject != jwt_principal.subject:
        return AuthorizationDecision("DENY", "MCP_SUBJECT_SUBSTITUTION")
    wallet = trust.active_wallet(jwt_principal.wallet, now)
    if wallet.subject != jwt_principal.subject or jwt_principal.role not in wallet.roles:
        return AuthorizationDecision("DENY", "REGISTRY_IDENTITY")
    if trust.agent_owners.get(binding.agent_id) != jwt_principal.subject:
        return AuthorizationDecision("DENY", "AGENT_OWNER")
    if trust.resource_owners.get(binding.resource_id) != jwt_principal.subject:
        return AuthorizationDecision("DENY", "RESOURCE_OWNER")
    if binding.operation != "RUN_TOOL" or jwt_principal.role != "OWNER":
        return AuthorizationDecision("DENY", "ROLE_OPERATION")
    if binding.tool != "recompute" or binding.destination != "mcp://local/recompute":
        return AuthorizationDecision("DENY", "TOOL_DESTINATION")
    if binding.service != "MCP":
        return AuthorizationDecision("DENY", "SERVICE")
    return AuthorizationDecision("ALLOW", "STRICT_OWNER_CONFINED_TOOL")
