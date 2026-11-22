"""Rule-based triage; scores/signals are never evaluated by policy.evaluate."""

from collections import defaultdict, deque

CONFIG = {"burst_window_ticks": 3, "burst_count": 3, "service_pivot_ticks": 12}
ADMIN_OPS = frozenset({"ADMIN_WRITE", "CREATE_SKILL", "REGISTER_MCP"})


def find(events):
    findings = []
    recent = defaultdict(lambda: deque())
    prior_gateway = {}
    for event in events:
        n = event["seq"]
        who = event["principal"]
        tick = event["tick"]
        observed = []
        if event["operation"] in ADMIN_OPS and event["token_role"] != "ADMIN":
            observed.append(("ROLE_ELEVATION_INTENT", [n]))
        if event["operation"] == "REGISTER_AGENT" and not event["ownership_proof"]:
            observed.append(("UNBOUND_AGENT_REGISTRATION", [n]))
        if event["operation"] in {"REGISTER_MCP", "MCP_CALL"} and event["destination"] in {"EXTERNAL", "PRIVATE_LAN"}:
            observed.append(("UNAPPROVED_MCP_TARGET", [n]))
        if event["operation"] in {"RUN_TOOL", "MCP_CALL", "REGISTER_MCP"} and event["payload"] != "SAFE":
            observed.append(("HIGH_RISK_TOOL_INTENT", [n]))
        if event["operation"] == "TELEGRAM_CALL" and (event["token_role"] != "SERVICE" or event["wallet"] != "wallet-telegram"):
            observed.append(("CROSS_SERVICE_IDENTITY_INTENT", [n]))
        if event["service"] in {"MCP", "RUNNER", "TELEGRAM"} and who in prior_gateway:
            earlier = prior_gateway[who]
            if tick - earlier["tick"] <= CONFIG["service_pivot_ticks"]:
                observed.append(("CROSS_SERVICE_SEQUENCE", [earlier["seq"], n]))
        if event["service"] == "GATEWAY":
            prior_gateway[who] = {"seq": n, "tick": tick}
        series = recent[who]
        while series and tick - series[0]["tick"] > CONFIG["burst_window_ticks"]:
            series.popleft()
        before = len(series)
        series.append({"tick": tick, "seq": n})
        if before < CONFIG["burst_count"] <= len(series):
            observed.append(("ACTIVITY_BURST", [x["seq"] for x in series][-CONFIG["burst_count"]:]))
        for kind, evidence in observed:
            findings.append({"seq": n, "kind": kind, "evidence_seqs": evidence})
    return sorted(findings, key=lambda row: (row["seq"], row["kind"]))
