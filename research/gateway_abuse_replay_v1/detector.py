"""Triage-only rules. This module has no authorization capability."""

from collections import defaultdict, deque

from .model import AGENT_OWNERS, SUBJECT_WALLETS

ADMIN_OPS = frozenset({"ADMIN_WRITE", "CREATE_SKILL", "REGISTER_MCP"})
SERVICE_OPS = {
    "MCP_CALL": ("svc-mcp", "wallet-mcp", "MCP"),
    "RUN_TOOL": ("svc-runner", "wallet-runner", "RUNNER"),
    "TELEGRAM_CALL": ("svc-telegram", "wallet-telegram", "TELEGRAM"),
}
SENSITIVE = frozenset({"REGISTER_AGENT", "ADMIN_WRITE", "CREATE_SKILL", "REGISTER_MCP", "MCP_CALL", "RUN_TOOL", "TELEGRAM_CALL"})
BURST_WINDOW = 3
BURST_COUNT = 3
PIVOT_WINDOW = 12


def find(events):
    findings = []
    recent_sensitive = defaultdict(deque)
    prior_gateway = {}
    for event in events:
        seq = event["seq"]
        tick = event["tick"]
        subject = event["request_subject"]
        operation = event["operation"]
        observed = []
        if operation not in {"HEALTH", "EXTERNAL_EFFECT"} and not event["token_verified"]:
            observed.append(("TOKEN_UNVERIFIED", [seq]))
        if event["token_subject"] != subject:
            observed.append(("SUBJECT_BINDING_MISMATCH", [seq]))
        if event["token_wallet"] != event["wallet"] or SUBJECT_WALLETS.get(subject) != event["wallet"]:
            observed.append(("WALLET_BINDING_MISMATCH", [seq]))
        expected_role = "ADMIN" if operation in ADMIN_OPS else "SERVICE" if operation in SERVICE_OPS else "OWNER" if operation in {"READ_AGENT", "REGISTER_AGENT", "SKILL_TEST"} else None
        if expected_role and event["token_role"] != expected_role:
            observed.append(("ROLE_CONFUSION", [seq]))
        if event["agent"] != "none" and AGENT_OWNERS.get(event["agent"]) != event["claimed_owner"]:
            observed.append(("RESOURCE_BINDING_MISMATCH", [seq]))
        if operation == "REGISTER_AGENT" and (not event["ownership_proof"] or AGENT_OWNERS.get(event["agent"]) != subject):
            observed.append(("UNAUTHORIZED_REGISTRATION", [seq]))
        if operation in {"REGISTER_MCP", "MCP_CALL"} and event["destination"] != "APPROVED":
            observed.append(("UNAPPROVED_MCP_TARGET", [seq]))
        if operation in {"RUN_TOOL", "MCP_CALL", "REGISTER_MCP"} and event["payload"] != "SAFE":
            observed.append(("HIGH_RISK_TOOL_INTENT", [seq]))
        if operation in SERVICE_OPS:
            expected_subject, expected_wallet, expected_service = SERVICE_OPS[operation]
            if subject != expected_subject or event["wallet"] != expected_wallet or event["service"] != expected_service:
                observed.append(("CROSS_SERVICE_IDENTITY_INTENT", [seq]))
        if event["service"] in {"MCP", "RUNNER", "TELEGRAM"} and subject in prior_gateway:
            earlier = prior_gateway[subject]
            if tick - earlier["tick"] <= PIVOT_WINDOW:
                observed.append(("CROSS_SERVICE_SEQUENCE", [earlier["seq"], seq]))
        if event["service"] == "GATEWAY":
            prior_gateway[subject] = {"seq": seq, "tick": tick}
        if operation in SENSITIVE:
            series = recent_sensitive[subject]
            while series and tick - series[0]["tick"] > BURST_WINDOW:
                series.popleft()
            before = len(series)
            series.append({"seq": seq, "tick": tick})
            if before < BURST_COUNT <= len(series):
                observed.append(("SENSITIVE_ACTIVITY_BURST", [row["seq"] for row in series][-BURST_COUNT:]))
        for kind, evidence in observed:
            findings.append({"seq": seq, "kind": kind, "evidence_seqs": evidence})
    return sorted(findings, key=lambda row: (row["seq"], row["kind"]))

