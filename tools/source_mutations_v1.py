"""Physical source mutation campaign in a disposable copy.

Every mutation has a fresh passing baseline, an exact one-token edit, a mutant
run, byte restoration, and a restored passing control. Test failures are KILLED;
timeouts/unexpected exits are CRASHED, never kills.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TEST = "test_gateway_abuse_replay_v1.py"
SPECS = [
    ("policy-token-verification", "research/gateway_abuse_replay_v1/policy.py", 'if not event["token_verified"]:', 'if False and not event["token_verified"]:'),
    ("policy-token-subject", "research/gateway_abuse_replay_v1/policy.py", 'if event["token_subject"] != subject:', 'if False and event["token_subject"] != subject:'),
    ("policy-token-wallet", "research/gateway_abuse_replay_v1/policy.py", 'if event["token_wallet"] != event["wallet"]:', 'if False and event["token_wallet"] != event["wallet"]:'),
    ("policy-subject-wallet", "research/gateway_abuse_replay_v1/policy.py", 'if SUBJECT_WALLETS.get(subject) != event["wallet"]:', 'if False and SUBJECT_WALLETS.get(subject) != event["wallet"]:'),
    ("policy-resource-owner", "research/gateway_abuse_replay_v1/policy.py", 'if expected is None or event["claimed_owner"] != expected:', 'if False and (expected is None or event["claimed_owner"] != expected):'),
    ("policy-admin-service", "research/gateway_abuse_replay_v1/policy.py", 'if event["service"] != "GATEWAY" or event["payload"] != "SAFE":', 'if event["payload"] != "SAFE":'),
    ("policy-service-binding", "research/gateway_abuse_replay_v1/policy.py", 'if role != "SERVICE" or subject != expected_subject or event["wallet"] != expected_wallet or event["service"] != expected_service:', 'if role != "SERVICE" or subject != expected_subject or event["wallet"] != expected_wallet:'),
    ("policy-health-payload", "research/gateway_abuse_replay_v1/policy.py", 'and event["destination"] == "INTERNAL" and event["payload"] == "SAFE"', 'and event["destination"] == "INTERNAL"'),
    ("detector-subject", "research/gateway_abuse_replay_v1/detector.py", 'observed.append(("SUBJECT_BINDING_MISMATCH", [seq]))', 'observed.append(("SUBJECT_BINDING_MUTANT", [seq]))'),
    ("detector-wallet", "research/gateway_abuse_replay_v1/detector.py", 'observed.append(("WALLET_BINDING_MISMATCH", [seq]))', 'observed.append(("WALLET_BINDING_MUTANT", [seq]))'),
    ("detector-resource", "research/gateway_abuse_replay_v1/detector.py", 'observed.append(("RESOURCE_BINDING_MISMATCH", [seq]))', 'observed.append(("RESOURCE_BINDING_MUTANT", [seq]))'),
    ("detector-mcp", "research/gateway_abuse_replay_v1/detector.py", 'observed.append(("UNAPPROVED_MCP_TARGET", [seq]))', 'observed.append(("UNAPPROVED_MCP_MUTANT", [seq]))'),
    ("detector-tool", "research/gateway_abuse_replay_v1/detector.py", 'observed.append(("HIGH_RISK_TOOL_INTENT", [seq]))', 'observed.append(("HIGH_RISK_TOOL_MUTANT", [seq]))'),
    ("detector-service", "research/gateway_abuse_replay_v1/detector.py", 'observed.append(("CROSS_SERVICE_IDENTITY_INTENT", [seq]))', 'observed.append(("CROSS_SERVICE_IDENTITY_MUTANT", [seq]))'),
    ("verifier-comparison", "research/gateway_abuse_replay_v1/verifier.py", 'if type(report) is not dict or report != recompute(events):', 'if type(report) is not dict or False:'),
    ("report-deny-classification", "research/gateway_abuse_replay_v1/report.py", 'status = "BLOCKED_BY_AUTHORIZATION"', 'status = "NOT_DETECTED"'),
]


def sha(raw): return hashlib.sha256(raw).hexdigest()


def test(cwd, timeout):
    try:
        process = subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", TEST, "-q"], cwd=cwd, capture_output=True, timeout=timeout)
        return {"exit_code": process.returncode, "stdout_sha256": sha(process.stdout), "stderr_sha256": sha(process.stderr), "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        return {"exit_code": None, "stdout_sha256": sha(exc.stdout or b""), "stderr_sha256": sha(exc.stderr or b""), "timed_out": True}


def run(out, timeout=30):
    results = []
    with tempfile.TemporaryDirectory(prefix="guardian-source-mutations-") as temp:
        root = Path(temp)
        shutil.copytree(ROOT / "research", root / "research")
        (root / "tests").mkdir(); shutil.copy2(ROOT / "tests" / TEST, root / "tests" / TEST)
        for name, relative, old, new in SPECS:
            path = root / relative; original = path.read_bytes(); text = original.decode("utf-8")
            baseline = test(root, timeout)
            count = text.count(old); applied = count == 1
            mutant = text.replace(old, new, 1).encode("utf-8") if applied else original
            path.write_bytes(mutant); mutated = test(root, timeout) if applied else {"exit_code": None, "timed_out": False}
            path.write_bytes(original); restored_bytes = path.read_bytes() == original; restored = test(root, timeout)
            if baseline["exit_code"] != 0 or not restored_bytes or restored["exit_code"] != 0:
                status = "CONTROL_BROKEN"
            elif not applied:
                status = "NOT_APPLIED"
            elif mutated.get("timed_out") or mutated.get("exit_code") not in (0, 1):
                status = "CRASHED"
            elif mutated["exit_code"] == 0:
                status = "SURVIVED"
            else:
                status = "KILLED"
            results.append({"mutation": name, "path": relative, "status": status, "match_count": count,
                            "applied": applied, "restored": restored_bytes, "original_sha256": sha(original),
                            "mutant_sha256": sha(mutant), "baseline": baseline, "mutated": mutated, "restored_control": restored})
    counts = {name: sum(row["status"] == name for row in results) for name in ("KILLED", "SURVIVED", "NOT_APPLIED", "CRASHED", "CONTROL_BROKEN")}
    report = {"schema": "guardian.source-mutations.v1", "population": len(results), "counts": counts, "results": results,
              "verdict": "PASS" if counts == {"KILLED": len(results), "SURVIVED": 0, "NOT_APPLIED": 0, "CRASHED": 0, "CONTROL_BROKEN": 0} else "HOLD"}
    out = Path(out); out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(json.dumps(report, sort_keys=True, indent=2).encode("ascii") + b"\n")
    print(json.dumps(report, sort_keys=True)); return report


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--out", type=Path, required=True); parser.add_argument("--timeout", type=int, default=30); args = parser.parse_args(argv)
    return 0 if run(args.out, args.timeout)["verdict"] == "PASS" else 1


if __name__ == "__main__": raise SystemExit(main())

