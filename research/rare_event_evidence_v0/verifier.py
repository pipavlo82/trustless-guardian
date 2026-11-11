"""Second-path recomputation. Shares schema/canonicalization; not independent code provenance."""

from .model import ACTIONS, OUTCOMES, CONFIG, REPORT_SCHEMA, MIN_BASELINE, digest


class ReportMismatch(ValueError):
    pass


def recompute(baseline, events):
    if len(baseline) < MIN_BASELINE:
        raise ReportMismatch("baseline too small")
    frequency = {}
    for item in baseline:
        key = item["action"] + ":" + item["outcome"]
        frequency[key] = frequency.get(key, 0) + 1
    population = len(baseline) + len(ACTIONS) * len(OUTCOMES)
    expected = []
    by_resource = {}
    # Independent reference traversal; no call to detector.produce_report.
    for i, event in enumerate(events):
        seq = i + 1
        signal_key = event["action"] + ":" + event["outcome"]
        if CONFIG["rare_threshold_denominator"] * (frequency.get(signal_key, 0) + 1) <= population:
            expected.append({"seq": seq, "kind": "RARE_PAIR", "evidence_seqs": [seq]})
        if event["outcome"] == "RECOVERY_REQUIRED":
            expected.append({"seq": seq, "kind": "RECOVERY_OBSERVED", "evidence_seqs": [seq]})
        group = (event["agent"], event["resource"])
        related = by_resource.setdefault(group, [])
        if event["outcome"] == "ALLOW":
            for old in reversed(related[-CONFIG["transition_window"]:]):
                if old["outcome"] == "DENY" and old["policy_revision"] != event["policy_revision"]:
                    expected.append({"seq": seq, "kind": "DENY_ALLOW_REVISION_CHANGE", "evidence_seqs": [old["seq"], seq]})
                    break
        before = sum(old["outcome"] == "DENY" for old in related[-CONFIG["deny_window"]:])
        after = sum(old["outcome"] == "DENY" for old in (related + [event])[-CONFIG["deny_window"]:])
        if before < CONFIG["deny_count"] <= after:
            evidence = [old["seq"] for old in (related + [event])[-CONFIG["deny_window"]:] if old["outcome"] == "DENY"]
            expected.append({"seq": seq, "kind": "DENIAL_BURST", "evidence_seqs": evidence[-CONFIG["deny_count"]:]})
        related.append(event)
    expected.sort(key=lambda f: (f["seq"], f["kind"]))
    return {
        "schema": REPORT_SCHEMA,
        "scope": "SYNTHETIC_READ_ONLY",
        "decision": "TRIAGE_ONLY",
        "baseline_sha256": digest(baseline),
        "events_sha256": digest(events),
        "baseline_count": len(baseline),
        "events_count": len(events),
        "config": dict(CONFIG),
        "finding_count": len(expected),
        "findings": expected,
    }


def verify_report(baseline, events, report):
    if not isinstance(report, dict) or report != recompute(baseline, events):
        raise ReportMismatch("REFUTED: report differs from second-path recomputation")
    return "RECOMPUTE_MATCH_UNAUTHENTICATED"
