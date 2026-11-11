"""Independent second traversal using list slicing, no detector.find import."""

THRESHOLD = 3
WINDOW = 3
PIVOT_WINDOW = 12


def find_reference(events):
    result = []
    for index, e in enumerate(events):
        n = index + 1
        alerts = {}
        o, service = e["operation"], e["service"]
        if o in {"ADMIN_WRITE", "CREATE_SKILL", "REGISTER_MCP"} and e["token_role"] != "ADMIN":
            alerts["ROLE_ELEVATION_INTENT"] = [n]
        if o == "REGISTER_AGENT" and e["ownership_proof"] is False:
            alerts["UNBOUND_AGENT_REGISTRATION"] = [n]
        if o in {"REGISTER_MCP", "MCP_CALL"} and e["destination"] in {"EXTERNAL", "PRIVATE_LAN"}:
            alerts["UNAPPROVED_MCP_TARGET"] = [n]
        if o in {"RUN_TOOL", "MCP_CALL", "REGISTER_MCP"} and e["payload"] != "SAFE":
            alerts["HIGH_RISK_TOOL_INTENT"] = [n]
        if o == "TELEGRAM_CALL" and (e["token_role"] != "SERVICE" or e["wallet"] != "wallet-telegram"):
            alerts["CROSS_SERVICE_IDENTITY_INTENT"] = [n]
        if service in {"MCP", "RUNNER", "TELEGRAM"}:
            for earlier in reversed(events[:index]):
                if (earlier["principal"] == e["principal"] and earlier["service"] == "GATEWAY"):
                    if e["tick"] - earlier["tick"] <= PIVOT_WINDOW:
                        alerts["CROSS_SERVICE_SEQUENCE"] = [earlier["seq"], n]
                    break
        prior = [x for x in events[:index]
                 if x["principal"] == e["principal"] and 0 <= e["tick"] - x["tick"] <= WINDOW]
        if len(prior) == THRESHOLD - 1:
            alerts["ACTIVITY_BURST"] = [x["seq"] for x in prior] + [n]
        for kind in sorted(alerts):
            result.append({"seq": n, "kind": kind, "evidence_seqs": alerts[kind]})
    return result
