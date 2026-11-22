"""Deterministic evidence-envelope assembly: simulation != enforcement."""

from collections import Counter

from .adapter import mapped_source_seqs, rare_report
from .detector import find
from .model import REPORT_SCHEMA, digest, validate_events
from .policy import evaluate

POLICY_PROFILE = "guardian.synthetic-gateway-policy.v0"


def assemble(events, decisions, findings, rare):
    by_event = {f["seq"] for f in findings}
    classifications = []
    for event, decision in zip(events, decisions):
        verdict = decision["verdict"]
        if verdict == "NOT_COVERED":
            label = "NOT_COVERED"
        elif verdict == "DENY":
            label = "BLOCKED_BY_AUTHORIZATION"
        elif event["seq"] in by_event:
            label = "DETECTED_ONLY"
        else:
            label = "NOT_DETECTED"
        classifications.append({"seq": event["seq"], "status": label})
    first_detect = min(by_event) if by_event else None
    first_deny = next((d["seq"] for d in decisions if d["verdict"] == "DENY"), None)
    return {
        "schema": REPORT_SCHEMA, "scope": "SYNTHETIC_OFFLINE_REPLAY_ONLY",
        "decision": "TRIAGE_AND_POLICY_SIMULATION_ONLY",
        "source_authentication": "NOT_ESTABLISHED",
        "enforcement": "NOT_EXECUTED",
        "policy_profile": POLICY_PROFILE,
        "events_sha256": digest(events), "event_count": len(events),
        "decisions": decisions, "findings": findings, "finding_count": len(findings),
        "classifications": classifications,
        "counts": dict(sorted(Counter(v["status"] for v in classifications).items())),
        "first_detection_seq": first_detect,
        "first_simulated_prevention_seq": first_deny,
        "rare_event_v0": {"source_seqs": mapped_source_seqs(events, decisions), "report": rare},
    }


def produce_report(events):
    validate_events(events)
    decisions = [{"seq": e["seq"], **evaluate(e)} for e in events]
    return assemble(events, decisions, find(events), rare_report(events, decisions))
