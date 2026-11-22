"""Reproduce the four independently identified v0 synthetic false-ALLOW cases."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.gateway_abuse_replay_v0.detector import find
from research.gateway_abuse_replay_v0.fixtures import event
from research.gateway_abuse_replay_v0.policy import evaluate


def cases():
    return (
        ("admin-subject-confusion", event(
            1, 1, principal="probe", wallet="wallet-admin", role="ADMIN",
            operation="ADMIN_WRITE",
        )),
        ("owner-resource-confusion", event(
            1, 1, principal="probe", wallet="wallet-legit", role="OWNER",
            operation="READ_AGENT", agent="agent-legit",
            registry_owner="wallet-legit",
        )),
        ("service-subject-confusion", event(
            1, 1, principal="legit", wallet="wallet-service", role="SERVICE",
            operation="RUN_TOOL", agent="none", registry_owner="none",
            proof=False, service="RUNNER", destination="INTERNAL",
        )),
        ("public-health-payload-confusion", event(
            1, 1, principal="guest", wallet="none", role="ANON",
            verified=False, operation="HEALTH", agent="none",
            registry_owner="none", proof=False, payload="UNSAFE_COMMAND",
        )),
    )


def audit():
    rows = []
    for name, record in cases():
        decision = evaluate(record)
        findings = find([record])
        rows.append({
            "case": name,
            "v0_policy": decision,
            "v0_detector": findings,
            "false_allow_reproduced": decision["verdict"] == "ALLOW",
            "detector_miss_reproduced": findings == [],
        })
    reproduced = all(row["false_allow_reproduced"] and row["detector_miss_reproduced"] for row in rows)
    return {
        "schema": "guardian.gateway-v0-binding-audit.v1",
        "scope": "SYNTHETIC_POLICY_SIMULATION_ONLY",
        "base_commit": "23bc33f81a7216b11efd7e614eb065275fd67a1e",
        "cases": rows,
        "reproduced": reproduced,
        "production_bypass_claim": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    report = audit()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(json.dumps(report, sort_keys=True, indent=2).encode("ascii") + b"\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["reproduced"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
