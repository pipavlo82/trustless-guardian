"""Separate report recomputation: independent policy, detection, and assembly paths.

Shares the published input parser, digest, and legacy rare-event adapter; this
is neither independent source provenance nor independent language/host trust.
"""

from collections import Counter

from research.rare_event_evidence_v0.verifier import recompute as recompute_rare

from .adapter import mapped_events, rare_baseline
from .detector_reference import find_reference
from .model import REPORT_SCHEMA, digest, validate_events
from .policy_reference import evaluate_reference


class ReplayMismatch(ValueError):
    pass


def recompute(events):
    validate_events(events)
    decisions = []
    for e in events:
        result = evaluate_reference(e)
        decisions.append({"seq": e["seq"], "verdict": result["verdict"], "reason": result["reason"]})
    findings = find_reference(events)
    finding_seq_set = set(row["seq"] for row in findings)
    classifications = []
    counters = Counter()
    for event in events:
        n = event["seq"]
        decision = decisions[n - 1]
        if decision["verdict"] == "NOT_COVERED":
            status = "NOT_COVERED"
        elif decision["verdict"] == "DENY":
            status = "BLOCKED_BY_AUTHORIZATION"
        elif n in finding_seq_set:
            status = "DETECTED_ONLY"
        else:
            status = "NOT_DETECTED"
        counters[status] += 1
        classifications.append({"seq": n, "status": status})
    covered_seqs = [item["seq"] for item in events
                    if decisions[item["seq"] - 1]["verdict"] != "NOT_COVERED"]
    return {
        "schema": REPORT_SCHEMA,
        "scope": "SYNTHETIC_OFFLINE_REPLAY_ONLY",
        "decision": "TRIAGE_AND_POLICY_SIMULATION_ONLY",
        "source_authentication": "NOT_ESTABLISHED",
        "enforcement": "NOT_EXECUTED",
        "policy_profile": "guardian.synthetic-gateway-policy.v0",
        "events_sha256": digest(events),
        "event_count": len(events),
        "decisions": decisions,
        "findings": findings,
        "finding_count": len(findings),
        "classifications": classifications,
        "counts": dict(sorted(counters.items())),
        "first_detection_seq": min(finding_seq_set) if finding_seq_set else None,
        "first_simulated_prevention_seq": next((d["seq"] for d in decisions if d["verdict"] == "DENY"), None),
        "rare_event_v0": {
            "source_seqs": covered_seqs,
            "report": recompute_rare(rare_baseline(), mapped_events(events, decisions)),
        },
    }


def verify_report(events, report):
    if type(report) is not dict or report != recompute(events):
        raise ReplayMismatch("REFUTED: full report differs from second-path recomputation")
    return "RECOMPUTE_MATCH_UNAUTHENTICATED_SYNTHETIC"
