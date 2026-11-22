"""Independent policy/detection/report recomputation for v1.

This deliberately duplicates the contract and does not import policy, detector,
or report. It still shares the parser and therefore is not independent provenance.
"""

from collections import Counter, defaultdict

from .model import AGENT_OWNERS, REPORT_SCHEMA, SUBJECT_WALLETS, digest, validate_events


class ReplayMismatch(ValueError):
    pass


def reference_decision(e):
    op = e["operation"]
    if op == "EXTERNAL_EFFECT": return {"verdict": "NOT_COVERED", "reason": "NO_EXTERNAL_OBSERVATION"}
    if op == "HEALTH":
        ok = (e["request_subject"] == e["token_subject"] == "guest" and e["wallet"] == e["token_wallet"] == "none"
              and e["token_role"] == "ANON" and not e["token_verified"] and e["agent"] == "none"
              and e["claimed_owner"] == "none" and not e["ownership_proof"] and e["service"] == "GATEWAY"
              and e["destination"] == "INTERNAL" and e["payload"] == "SAFE")
        return {"verdict": "ALLOW" if ok else "DENY", "reason": "PUBLIC_HEALTH_ONLY" if ok else "PUBLIC_HEALTH_SHAPE"}
    checks = [
        (e["token_verified"], "TOKEN_NOT_VERIFIED"),
        (e["token_subject"] == e["request_subject"], "TOKEN_SUBJECT_MISMATCH"),
        (e["token_wallet"] == e["wallet"], "TOKEN_WALLET_MISMATCH"),
        (SUBJECT_WALLETS.get(e["request_subject"]) == e["wallet"], "SUBJECT_WALLET_MISMATCH"),
    ]
    if op in {"ADMIN_WRITE", "CREATE_SKILL", "REGISTER_MCP"}:
        checks.extend([(e["request_subject"] == "admin" and e["token_role"] == "ADMIN" and e["wallet"] == "wallet-admin", "ADMIN_SUBJECT_ROLE_WALLET_REQUIRED"),
                       (e["service"] == "GATEWAY" and e["payload"] == "SAFE", "ADMIN_REQUEST_SCOPE_DENIED")])
        if op == "REGISTER_MCP":
            checks.extend([(e["agent"] == "none" and e["claimed_owner"] == "none" and not e["ownership_proof"], "ADMIN_RESOURCE_SHAPE"),
                           (e["destination"] == "APPROVED", "MCP_DESTINATION_NOT_APPROVED")])
        else:
            checks.extend([(AGENT_OWNERS.get(e["agent"]) == e["claimed_owner"], "RESOURCE_OWNER_MISMATCH"),
                           (e["destination"] == "INTERNAL", "ADMIN_DESTINATION_DENIED")])
        success = "SYNTHETIC_ADMIN_POLICY_V1"
    elif op in {"READ_AGENT", "REGISTER_AGENT", "SKILL_TEST"}:
        checks.extend([(e["token_role"] == "OWNER" and e["request_subject"] in {"owner-a", "owner-b"}, "OWNER_SUBJECT_ROLE_REQUIRED"),
                       (AGENT_OWNERS.get(e["agent"]) == e["claimed_owner"] == e["request_subject"], "RESOURCE_OWNER_MISMATCH"),
                       (e["ownership_proof"], "REGISTRY_PROOF_REQUIRED"),
                       (e["service"] == "GATEWAY" and e["payload"] == "SAFE" and e["destination"] in {"INTERNAL", "APPROVED"}, "OWNER_REQUEST_SCOPE_DENIED")])
        success = "SYNTHETIC_OWNER_POLICY_V1"
    elif op in {"MCP_CALL", "RUN_TOOL", "TELEGRAM_CALL"}:
        expected = {"MCP_CALL": ("svc-mcp", "wallet-mcp", "MCP", "APPROVED"), "RUN_TOOL": ("svc-runner", "wallet-runner", "RUNNER", "INTERNAL"), "TELEGRAM_CALL": ("svc-telegram", "wallet-telegram", "TELEGRAM", "INTERNAL")}[op]
        checks.extend([(e["token_role"] == "SERVICE" and (e["request_subject"], e["wallet"], e["service"]) == expected[:3], "SERVICE_SUBJECT_ROLE_WALLET_REQUIRED"),
                       (AGENT_OWNERS.get(e["agent"]) == e["claimed_owner"], "RESOURCE_OWNER_MISMATCH"),
                       (e["payload"] == "SAFE", "TOOL_PAYLOAD_NOT_ALLOWED"),
                       (e["destination"] == expected[3], "DESTINATION_OUTSIDE_POLICY")])
        success = "SYNTHETIC_SERVICE_POLICY_V1"
    else:
        return {"verdict": "DENY", "reason": "UNKNOWN_OPERATION"}
    for allowed, reason in checks:
        if not allowed: return {"verdict": "DENY", "reason": reason}
    return {"verdict": "ALLOW", "reason": success}


def reference_find(events):
    rows = []
    prior_gateway = {}
    sensitive = defaultdict(list)
    for index, e in enumerate(events):
        seq, op, subject = index + 1, e["operation"], e["request_subject"]
        alerts = {}
        if op not in {"HEALTH", "EXTERNAL_EFFECT"} and not e["token_verified"]: alerts["TOKEN_UNVERIFIED"] = [seq]
        if e["token_subject"] != subject: alerts["SUBJECT_BINDING_MISMATCH"] = [seq]
        if e["token_wallet"] != e["wallet"] or SUBJECT_WALLETS.get(subject) != e["wallet"]: alerts["WALLET_BINDING_MISMATCH"] = [seq]
        expected_role = "ADMIN" if op in {"ADMIN_WRITE", "CREATE_SKILL", "REGISTER_MCP"} else "SERVICE" if op in {"MCP_CALL", "RUN_TOOL", "TELEGRAM_CALL"} else "OWNER" if op in {"READ_AGENT", "REGISTER_AGENT", "SKILL_TEST"} else None
        if expected_role and e["token_role"] != expected_role: alerts["ROLE_CONFUSION"] = [seq]
        if e["agent"] != "none" and AGENT_OWNERS.get(e["agent"]) != e["claimed_owner"]: alerts["RESOURCE_BINDING_MISMATCH"] = [seq]
        if op == "REGISTER_AGENT" and (not e["ownership_proof"] or AGENT_OWNERS.get(e["agent"]) != subject): alerts["UNAUTHORIZED_REGISTRATION"] = [seq]
        if op in {"REGISTER_MCP", "MCP_CALL"} and e["destination"] != "APPROVED": alerts["UNAPPROVED_MCP_TARGET"] = [seq]
        if op in {"RUN_TOOL", "MCP_CALL", "REGISTER_MCP"} and e["payload"] != "SAFE": alerts["HIGH_RISK_TOOL_INTENT"] = [seq]
        service_expected = {"MCP_CALL": ("svc-mcp", "wallet-mcp", "MCP"), "RUN_TOOL": ("svc-runner", "wallet-runner", "RUNNER"), "TELEGRAM_CALL": ("svc-telegram", "wallet-telegram", "TELEGRAM")}.get(op)
        if service_expected and (subject, e["wallet"], e["service"]) != service_expected: alerts["CROSS_SERVICE_IDENTITY_INTENT"] = [seq]
        if e["service"] in {"MCP", "RUNNER", "TELEGRAM"} and subject in prior_gateway and e["tick"] - prior_gateway[subject]["tick"] <= 12: alerts["CROSS_SERVICE_SEQUENCE"] = [prior_gateway[subject]["seq"], seq]
        if e["service"] == "GATEWAY": prior_gateway[subject] = {"seq": seq, "tick": e["tick"]}
        if op in {"REGISTER_AGENT", "ADMIN_WRITE", "CREATE_SKILL", "REGISTER_MCP", "MCP_CALL", "RUN_TOOL", "TELEGRAM_CALL"}:
            history = sensitive[subject]
            history[:] = [row for row in history if e["tick"] - row["tick"] <= 3]
            before = len(history); history.append({"seq": seq, "tick": e["tick"]})
            if before < 3 <= len(history): alerts["SENSITIVE_ACTIVITY_BURST"] = [row["seq"] for row in history][-3:]
        for kind in sorted(alerts): rows.append({"seq": seq, "kind": kind, "evidence_seqs": alerts[kind]})
    return rows


def recompute(events):
    validate_events(events)
    decisions = [{"seq": e["seq"], **reference_decision(e)} for e in events]
    findings = reference_find(events); flagged = {row["seq"] for row in findings}; classifications = []
    for e, decision in zip(events, decisions):
        status = "NOT_COVERED" if decision["verdict"] == "NOT_COVERED" else "BLOCKED_BY_AUTHORIZATION" if decision["verdict"] == "DENY" else "DETECTED_ONLY" if e["seq"] in flagged else "NOT_DETECTED"
        classifications.append({"seq": e["seq"], "status": status})
    return {"schema": REPORT_SCHEMA, "scope": "SYNTHETIC_OFFLINE_REPLAY_ONLY", "decision": "TRIAGE_AND_POLICY_SIMULATION_ONLY",
            "source_authentication": "NOT_ESTABLISHED", "enforcement": "NOT_EXECUTED", "policy_profile": "guardian.synthetic-gateway-policy.v1",
            "events_sha256": digest(events), "event_count": len(events), "decisions": decisions, "findings": findings,
            "finding_count": len(findings), "classifications": classifications,
            "counts": dict(sorted(Counter(row["status"] for row in classifications).items())),
            "first_detection_seq": min(flagged) if flagged else None,
            "first_simulated_prevention_seq": next((row["seq"] for row in decisions if row["verdict"] == "DENY"), None)}


def verify_report(events, report):
    if type(report) is not dict or report != recompute(events):
        raise ReplayMismatch("REFUTED: full v1 report differs from independent recomputation")
    return "RECOMPUTE_MATCH_UNAUTHENTICATED_SYNTHETIC_V1"

