"""Synthetic policy-evaluation model, NOT a gateway or OS enforcement adapter.

The validation booleans are *fabricated harness fixtures*, never a crypto proof.
The policy does not execute requests; BLOCKED is a counterfactual simulation.
"""

ADMIN_OPS = frozenset({"ADMIN_WRITE", "CREATE_SKILL", "REGISTER_MCP"})


def evaluate(event):
    op = event["operation"]
    if op == "EXTERNAL_EFFECT":
        return {"verdict": "NOT_COVERED", "reason": "NO_EXTERNAL_OBSERVATION"}
    if op == "HEALTH":
        return {"verdict": "ALLOW", "reason": "PUBLIC_HEALTH_ONLY"}
    if not event["token_verified"]:
        return {"verdict": "DENY", "reason": "TOKEN_NOT_VERIFIED"}
    role = event["token_role"]
    wallet = event["wallet"]
    if op in ADMIN_OPS:
        if role != "ADMIN" or wallet != "wallet-admin":
            return {"verdict": "DENY", "reason": "ADMIN_WALLET_ROLE_REQUIRED"}
        if event["payload"] != "SAFE":
            return {"verdict": "DENY", "reason": "ADMIN_PAYLOAD_NOT_APPROVED"}
        if op == "REGISTER_MCP" and event["destination"] != "APPROVED":
            return {"verdict": "DENY", "reason": "MCP_DESTINATION_NOT_APPROVED"}
        return {"verdict": "ALLOW", "reason": "SYNTHETIC_ADMIN_POLICY"}
    if op in {"READ_AGENT", "REGISTER_AGENT", "SKILL_TEST"}:
        if role != "OWNER" or wallet != event["registry_owner"]:
            return {"verdict": "DENY", "reason": "OWNER_WALLET_REQUIRED"}
        if not event["ownership_proof"] or event["agent"] == "agent-unknown":
            return {"verdict": "DENY", "reason": "REGISTRY_PROOF_REQUIRED"}
        if op == "SKILL_TEST" and (event["payload"] != "SAFE" or event["destination"] not in {"INTERNAL", "APPROVED"}):
            return {"verdict": "DENY", "reason": "SKILL_TEST_SCOPE_DENIED"}
        return {"verdict": "ALLOW", "reason": "SYNTHETIC_OWNER_POLICY"}
    if op in {"MCP_CALL", "RUN_TOOL", "TELEGRAM_CALL"}:
        target_wallet = "wallet-telegram" if op == "TELEGRAM_CALL" else "wallet-service"
        target_service = "TELEGRAM" if op == "TELEGRAM_CALL" else ("RUNNER" if op == "RUN_TOOL" else "MCP")
        if role != "SERVICE" or wallet != target_wallet or event["service"] != target_service:
            return {"verdict": "DENY", "reason": "SERVICE_IDENTITY_REQUIRED"}
        if event["payload"] != "SAFE":
            return {"verdict": "DENY", "reason": "TOOL_PAYLOAD_NOT_ALLOWED"}
        if event["destination"] not in ({"INTERNAL"} if op in {"RUN_TOOL", "TELEGRAM_CALL"} else {"APPROVED"}):
            return {"verdict": "DENY", "reason": "DESTINATION_OUTSIDE_POLICY"}
        return {"verdict": "ALLOW", "reason": "SYNTHETIC_SERVICE_POLICY"}
    # Should be unreachable because validate_events enforces the operation enum.
    return {"verdict": "DENY", "reason": "UNKNOWN_OPERATION"}
