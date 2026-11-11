"""Separate declarative authorization oracle; no import from policy.py."""


def evaluate_reference(e):
    o = e["operation"]
    # Conditions ordered by contract, not by replay findings or risk scores.
    if o == "EXTERNAL_EFFECT":
        return {"verdict": "NOT_COVERED", "reason": "NO_EXTERNAL_OBSERVATION"}
    if o == "HEALTH":
        return {"verdict": "ALLOW", "reason": "PUBLIC_HEALTH_ONLY"}

    checks = [(e["token_verified"], "TOKEN_NOT_VERIFIED")]
    if o in {"ADMIN_WRITE", "CREATE_SKILL", "REGISTER_MCP"}:
        checks.extend([
            (e["token_role"] == "ADMIN" and e["wallet"] == "wallet-admin", "ADMIN_WALLET_ROLE_REQUIRED"),
            (e["payload"] == "SAFE", "ADMIN_PAYLOAD_NOT_APPROVED"),
        ])
        if o == "REGISTER_MCP":
            checks.append((e["destination"] == "APPROVED", "MCP_DESTINATION_NOT_APPROVED"))
        success = "SYNTHETIC_ADMIN_POLICY"
    elif o in {"READ_AGENT", "REGISTER_AGENT", "SKILL_TEST"}:
        checks.extend([
            (e["token_role"] == "OWNER" and e["wallet"] == e["registry_owner"], "OWNER_WALLET_REQUIRED"),
            (e["ownership_proof"] and e["agent"] != "agent-unknown", "REGISTRY_PROOF_REQUIRED"),
        ])
        if o == "SKILL_TEST":
            checks.append((e["payload"] == "SAFE" and e["destination"] in {"INTERNAL", "APPROVED"},
                           "SKILL_TEST_SCOPE_DENIED"))
        success = "SYNTHETIC_OWNER_POLICY"
    elif o in {"MCP_CALL", "RUN_TOOL", "TELEGRAM_CALL"}:
        expected = {
            "MCP_CALL": ("wallet-service", "MCP", ("APPROVED",)),
            "RUN_TOOL": ("wallet-service", "RUNNER", ("INTERNAL",)),
            "TELEGRAM_CALL": ("wallet-telegram", "TELEGRAM", ("INTERNAL",)),
        }[o]
        checks.extend([
            (e["token_role"] == "SERVICE" and e["wallet"] == expected[0] and e["service"] == expected[1], "SERVICE_IDENTITY_REQUIRED"),
            (e["payload"] == "SAFE", "TOOL_PAYLOAD_NOT_ALLOWED"),
            (e["destination"] in expected[2], "DESTINATION_OUTSIDE_POLICY"),
        ])
        success = "SYNTHETIC_SERVICE_POLICY"
    else:
        return {"verdict": "DENY", "reason": "UNKNOWN_OPERATION"}
    for is_allowed, reason in checks:
        if not is_allowed:
            return {"verdict": "DENY", "reason": reason}
    return {"verdict": "ALLOW", "reason": success}
