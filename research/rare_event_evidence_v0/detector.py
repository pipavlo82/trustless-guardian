"""Triage signals only; neither statistical findings nor hashes authorize actions."""

from collections import Counter, defaultdict, deque

from .model import ACTIONS, OUTCOMES, CONFIG, REPORT_SCHEMA, MIN_BASELINE, digest


def produce_report(baseline, events):
    if len(baseline) < MIN_BASELINE:
        raise ValueError("baseline too small")
    counts = Counter((e["action"], e["outcome"]) for e in baseline)
    # Add-one smoothing over a fixed, declared alphabet. Exact integer decision.
    denominator = len(baseline) + len(ACTIONS) * len(OUTCOMES)
    findings = []
    histories = defaultdict(lambda: deque(maxlen=CONFIG["deny_window"]))
    for event in events:
        seq = event["seq"]
        key = (event["agent"], event["resource"])
        history = histories[key]
        pair = (event["action"], event["outcome"])
        if (counts[pair] + 1) * CONFIG["rare_threshold_denominator"] <= denominator:
            findings.append({"seq": seq, "kind": "RARE_PAIR", "evidence_seqs": [seq]})
        if event["outcome"] == "RECOVERY_REQUIRED":
            findings.append({"seq": seq, "kind": "RECOVERY_OBSERVED", "evidence_seqs": [seq]})
        recent = list(history)
        if event["outcome"] == "ALLOW":
            matched = next((prior for prior in reversed(recent[-CONFIG["transition_window"]:])
                            if prior["outcome"] == "DENY" and prior["policy_revision"] != event["policy_revision"]), None)
            if matched is not None:
                findings.append({"seq": seq, "kind": "DENY_ALLOW_REVISION_CHANGE", "evidence_seqs": [matched["seq"], seq]})
        before = [prior["seq"] for prior in recent if prior["outcome"] == "DENY"]
        history.append(event)
        after = [prior["seq"] for prior in history if prior["outcome"] == "DENY"]
        if len(before) < CONFIG["deny_count"] <= len(after):
            findings.append({"seq": seq, "kind": "DENIAL_BURST", "evidence_seqs": after[-CONFIG["deny_count"]:]})
    findings.sort(key=lambda f: (f["seq"], f["kind"]))
    return {
        "schema": REPORT_SCHEMA,
        "scope": "SYNTHETIC_READ_ONLY",
        "decision": "TRIAGE_ONLY",
        "baseline_sha256": digest(baseline),
        "events_sha256": digest(events),
        "baseline_count": len(baseline),
        "events_count": len(events),
        "config": dict(CONFIG),
        "finding_count": len(findings),
        "findings": findings,
    }
