"""Synthetic authorization oracle v1. It never executes an action.

Detection is intentionally absent from this module: suspicious activity cannot
grant permission and detector output is not an authorization input.
"""

from .model import AGENT_OWNERS, SUBJECT_WALLETS

ADMIN_OPS = frozenset({"ADMIN_WRITE", "CREATE_SKILL", "REGISTER_MCP"})
OWNER_OPS = frozenset({"READ_AGENT", "REGISTER_AGENT", "SKILL_TEST"})
SERVICE_BINDINGS = {
    "MCP_CALL": ("svc-mcp", "wallet-mcp", "MCP", "APPROVED"),
    "RUN_TOOL": ("svc-runner", "wallet-runner", "RUNNER", "INTERNAL"),
    "TELEGRAM_CALL": ("svc-telegram", "wallet-telegram", "TELEGRAM", "INTERNAL"),
}


def result(verdict, reason):
    return {"verdict": verdict, "reason": reason}


def _identity(event):
    subject = event["request_subject"]
    if not event["token_verified"]:
        return "TOKEN_NOT_VERIFIED"
    if event["token_subject"] != subject:
        return "TOKEN_SUBJECT_MISMATCH"
    if event["token_wallet"] != event["wallet"]:
        return "TOKEN_WALLET_MISMATCH"
    if SUBJECT_WALLETS.get(subject) != event["wallet"]:
        return "SUBJECT_WALLET_MISMATCH"
    return None


def _resource(event):
    agent = event["agent"]
    expected = AGENT_OWNERS.get(agent)
    if expected is None or event["claimed_owner"] != expected:
        return "RESOURCE_OWNER_MISMATCH"
    return None


def evaluate(event):
    operation = event["operation"]
    if operation == "EXTERNAL_EFFECT":
        return result("NOT_COVERED", "NO_EXTERNAL_OBSERVATION")
    if operation == "HEALTH":
        exact_public = (
            event["request_subject"] == event["token_subject"] == "guest"
            and event["wallet"] == event["token_wallet"] == "none"
            and event["token_role"] == "ANON"
            and not event["token_verified"]
            and event["agent"] == "none" and event["claimed_owner"] == "none"
            and not event["ownership_proof"] and event["service"] == "GATEWAY"
            and event["destination"] == "INTERNAL" and event["payload"] == "SAFE"
        )
        return result("ALLOW", "PUBLIC_HEALTH_ONLY") if exact_public else result("DENY", "PUBLIC_HEALTH_SHAPE")

    identity_error = _identity(event)
    if identity_error:
        return result("DENY", identity_error)

    subject = event["request_subject"]
    role = event["token_role"]
    if operation in ADMIN_OPS:
        if subject != "admin" or role != "ADMIN" or event["wallet"] != "wallet-admin":
            return result("DENY", "ADMIN_SUBJECT_ROLE_WALLET_REQUIRED")
        if event["service"] != "GATEWAY" or event["payload"] != "SAFE":
            return result("DENY", "ADMIN_REQUEST_SCOPE_DENIED")
        if operation == "REGISTER_MCP":
            if event["agent"] != "none" or event["claimed_owner"] != "none" or event["ownership_proof"]:
                return result("DENY", "ADMIN_RESOURCE_SHAPE")
            if event["destination"] != "APPROVED":
                return result("DENY", "MCP_DESTINATION_NOT_APPROVED")
        else:
            resource_error = _resource(event)
            if resource_error:
                return result("DENY", resource_error)
            if event["destination"] != "INTERNAL":
                return result("DENY", "ADMIN_DESTINATION_DENIED")
        return result("ALLOW", "SYNTHETIC_ADMIN_POLICY_V1")

    if operation in OWNER_OPS:
        if role != "OWNER" or subject not in {"owner-a", "owner-b"}:
            return result("DENY", "OWNER_SUBJECT_ROLE_REQUIRED")
        resource_error = _resource(event)
        if resource_error or AGENT_OWNERS[event["agent"]] != subject:
            return result("DENY", "RESOURCE_OWNER_MISMATCH")
        if not event["ownership_proof"]:
            return result("DENY", "REGISTRY_PROOF_REQUIRED")
        if event["service"] != "GATEWAY" or event["payload"] != "SAFE" or event["destination"] not in {"INTERNAL", "APPROVED"}:
            return result("DENY", "OWNER_REQUEST_SCOPE_DENIED")
        return result("ALLOW", "SYNTHETIC_OWNER_POLICY_V1")

    if operation in SERVICE_BINDINGS:
        expected_subject, expected_wallet, expected_service, expected_destination = SERVICE_BINDINGS[operation]
        if role != "SERVICE" or subject != expected_subject or event["wallet"] != expected_wallet or event["service"] != expected_service:
            return result("DENY", "SERVICE_SUBJECT_ROLE_WALLET_REQUIRED")
        resource_error = _resource(event)
        if resource_error:
            return result("DENY", resource_error)
        if event["payload"] != "SAFE":
            return result("DENY", "TOOL_PAYLOAD_NOT_ALLOWED")
        if event["destination"] != expected_destination:
            return result("DENY", "DESTINATION_OUTSIDE_POLICY")
        return result("ALLOW", "SYNTHETIC_SERVICE_POLICY_V1")

    return result("DENY", "UNKNOWN_OPERATION")

