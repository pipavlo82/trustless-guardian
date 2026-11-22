"""Versioned mapping onto read-only rare-event v0; never promotes its signals."""

from research.rare_event_evidence_v0.detector import produce_report
from research.rare_event_evidence_v0.fixtures import fixture_sets
from research.rare_event_evidence_v0.model import EVENT_SCHEMA


def rare_baseline():
    return fixture_sets()["baseline.jsonl"]


def mapped_events(events, decisions):
    operation_map = {
        "HEALTH": "READ", "READ_AGENT": "READ", "REGISTER_AGENT": "WRITE",
        "ADMIN_WRITE": "POLICY_CHANGE", "CREATE_SKILL": "WRITE", "REGISTER_MCP": "WRITE",
        "SKILL_TEST": "READ", "MCP_CALL": "READ", "RUN_TOOL": "POLICY_CHANGE",
        "TELEGRAM_CALL": "READ", "EXTERNAL_EFFECT": "READ",
    }
    # Unknown external effects have NO authorization outcome; exclude them rather
    # than incorrectly translating NOT_COVERED into ALLOW/RECOVERY_REQUIRED.
    covered = [(e, decision) for e, decision in zip(events, decisions) if decision["verdict"] != "NOT_COVERED"]
    return [{"schema": EVENT_SCHEMA, "origin": "synthetic", "seq": n,
             "agent": "agent-" + e["principal"], "resource": "service-" + e["service"].lower(),
             "action": operation_map[e["operation"]],
             "outcome": "DENY" if decision["verdict"] == "DENY" else "ALLOW",
             "policy_revision": 1}
            for n, (e, decision) in enumerate(covered, 1)]


def rare_report(events, decisions):
    return produce_report(rare_baseline(), mapped_events(events, decisions))


def mapped_source_seqs(events, decisions):
    return [e["seq"] for e, d in zip(events, decisions) if d["verdict"] != "NOT_COVERED"]
