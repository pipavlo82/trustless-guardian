"""Deterministic synthetic training/benign/anomaly populations."""

from pathlib import Path

from .model import EVENT_SCHEMA, encode_events


def event(seq, action="WRITE", outcome="ALLOW", *, agent="agent-a", resource="resource-a", policy_revision=1):
    return {
        "schema": EVENT_SCHEMA, "origin": "synthetic", "seq": seq,
        "agent": agent, "resource": resource, "action": action,
        "outcome": outcome, "policy_revision": policy_revision,
    }


def fixture_sets():
    baseline = [event(i, action="READ" if i % 3 == 0 else "WRITE",
                      agent="agent-a" if i % 2 else "agent-b") for i in range(1, 241)]
    benign = [event(i, action="READ" if i % 3 == 0 else "WRITE",
                    agent="agent-b" if i % 2 else "agent-a") for i in range(1, 81)]
    anomaly = [event(i, outcome="DENY") for i in range(1, 5)]
    anomaly += [event(5, action="POLICY_CHANGE", policy_revision=2),
                event(6, outcome="ALLOW", policy_revision=2),
                event(7, outcome="RECOVERY_REQUIRED", policy_revision=2)]
    return {"baseline.jsonl": baseline, "benign.jsonl": benign, "anomaly.jsonl": anomaly}


def write_fixtures(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for name, events in fixture_sets().items():
        (directory / name).write_bytes(encode_events(events))
