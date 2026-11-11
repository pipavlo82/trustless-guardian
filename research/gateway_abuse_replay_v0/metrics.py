"""Event-level evaluation on independent generated, labelled synthetic streams."""

from .fixtures import holdout_corpus
from .report import produce_report


def evaluate_holdout():
    tp = fp = tn = fn = denied_mal = 0
    per_stream = []
    for name, events, malicious in holdout_corpus():
        outcome = produce_report(events)
        labelled = set(malicious)
        flagged = {f["seq"] for f in outcome["findings"]}
        denied = {x["seq"] for x in outcome["decisions"] if x["verdict"] == "DENY"}
        tp += len(flagged & labelled)
        fn += len(labelled - flagged)
        fp += len(flagged - labelled)
        tn += len({e["seq"] for e in events} - flagged - labelled)
        denied_mal += len(denied & labelled)
        per_stream.append({
            "fixture": name, "event_count": len(events), "synthetic_positive_count": len(labelled),
            "detected_positive_count": len(flagged & labelled), "false_positive_count": len(flagged - labelled),
            "simulated_denied_positive_count": len(denied & labelled),
            "first_detection_seq": outcome["first_detection_seq"],
            "first_simulated_prevention_seq": outcome["first_simulated_prevention_seq"],
        })
    return {
        "schema": "guardian.gateway-abuse-holdout.v0",
        "scope": "DETERMINISTIC_SYNTHETIC_ONLY",
        "unit": "event", "label_source": "fixture_annotations_not_detector",
        "dataset": "six benign streams + six attack streams, no real telemetry",
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "false_positive_rate": {"numerator": fp, "denominator": fp + tn},
        "false_negative_rate": {"numerator": fn, "denominator": tp + fn},
        "simulated_denied_malicious_count": denied_mal,
        "per_stream": per_stream,
        "statistical_inference": "NOT_ESTABLISHED",
        "real_world_generalization": "NOT_COVERED",
    }
