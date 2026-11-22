"""Deterministic report assembly. Simulated DENY is not observed enforcement."""

from collections import Counter

from .detector import find
from .model import REPORT_SCHEMA, digest, validate_events
from .policy import evaluate

POLICY_PROFILE = "guardian.synthetic-gateway-policy.v1"


def produce_report(events):
    validate_events(events)
    decisions = [{"seq": event["seq"], **evaluate(event)} for event in events]
    findings = find(events)
    finding_seqs = {row["seq"] for row in findings}
    classifications = []
    for event, decision in zip(events, decisions):
        if decision["verdict"] == "NOT_COVERED":
            status = "NOT_COVERED"
        elif decision["verdict"] == "DENY":
            status = "BLOCKED_BY_AUTHORIZATION"
        elif event["seq"] in finding_seqs:
            status = "DETECTED_ONLY"
        else:
            status = "NOT_DETECTED"
        classifications.append({"seq": event["seq"], "status": status})
    return {
        "schema": REPORT_SCHEMA,
        "scope": "SYNTHETIC_OFFLINE_REPLAY_ONLY",
        "decision": "TRIAGE_AND_POLICY_SIMULATION_ONLY",
        "source_authentication": "NOT_ESTABLISHED",
        "enforcement": "NOT_EXECUTED",
        "policy_profile": POLICY_PROFILE,
        "events_sha256": digest(events),
        "event_count": len(events),
        "decisions": decisions,
        "findings": findings,
        "finding_count": len(findings),
        "classifications": classifications,
        "counts": dict(sorted(Counter(row["status"] for row in classifications).items())),
        "first_detection_seq": min(finding_seqs) if finding_seqs else None,
        "first_simulated_prevention_seq": next((row["seq"] for row in decisions if row["verdict"] == "DENY"), None),
    }

