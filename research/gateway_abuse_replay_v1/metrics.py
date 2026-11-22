"""Compare v0 and v1 detectors on the same predeclared v1 holdout."""

from research.gateway_abuse_replay_v0.detector import find as find_v0

from .detector import find as find_v1
from .heldout import corpus


def _project_v0(events):
    subject = {"guest": "guest", "owner-a": "legit", "owner-b": "probe", "admin": "legit",
               "svc-runner": "service", "svc-mcp": "service", "svc-telegram": "telegram", "attacker": "probe"}
    wallet = {"none": "none", "wallet-a": "wallet-legit", "wallet-b": "wallet-probe", "wallet-admin": "wallet-admin",
              "wallet-runner": "wallet-service", "wallet-mcp": "wallet-service", "wallet-telegram": "wallet-telegram", "wallet-attacker": "wallet-probe"}
    agent = {"none": "none", "agent-a": "agent-legit", "agent-b": "agent-probe", "agent-pending-a": "agent-probe", "agent-admin": "agent-legit"}
    owner_wallet = {"none": "none", "owner-a": "wallet-legit", "owner-b": "wallet-probe", "admin": "wallet-admin"}
    return [{
        "seq": e["seq"], "tick": e["tick"], "principal": subject[e["request_subject"]],
        "wallet": wallet[e["wallet"]], "token_role": e["token_role"], "token_verified": e["token_verified"],
        "operation": e["operation"], "agent": agent[e["agent"]], "registry_owner": owner_wallet[e["claimed_owner"]],
        "ownership_proof": e["ownership_proof"], "service": e["service"], "destination": e["destination"], "payload": e["payload"],
    } for e in events]


def _matrix(detector, projector=lambda rows: rows):
    tp = fp = tn = fn = 0
    streams = []
    for name, events, positives in corpus():
        labelled = set(positives)
        flagged = {row["seq"] for row in detector(projector(events))}
        population = {event["seq"] for event in events}
        tp += len(flagged & labelled); fp += len(flagged - labelled)
        fn += len(labelled - flagged); tn += len(population - flagged - labelled)
        streams.append({"fixture": name, "events": len(events), "labelled_positive": len(labelled),
                        "true_positive": len(flagged & labelled), "false_positive": len(flagged - labelled)})
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "streams": streams}


def evaluate_holdout():
    baseline = _matrix(find_v0, _project_v0)
    repair = _matrix(find_v1)
    return {
        "schema": "guardian.gateway-abuse-holdout.v1",
        "scope": "PREDECLARED_SYNTHETIC_ONLY",
        "unit": "event",
        "dataset": "four benign administrative/owner/service streams plus eight attack-class streams",
        "labels_available_to_detector": False,
        "v0_projection": baseline,
        "v1": repair,
        "improvement": {"additional_true_positives": repair["TP"] - baseline["TP"],
                        "fewer_false_positives": baseline["FP"] - repair["FP"],
                        "fewer_false_negatives": baseline["FN"] - repair["FN"]},
        "statistical_inference": "NOT_ESTABLISHED",
        "real_world_generalization": "NOT_COVERED",
    }

