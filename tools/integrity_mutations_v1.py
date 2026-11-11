"""Physical negative controls for the layered integrity verifier.

Each case starts from a passing checkout, changes one real path, verifies that
the change is rejected, restores the original bytes, and reruns the control.
No mutation is reported as killed when either control is unhealthy.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPECS = (
    ("modified-legacy-file", "append", "README.md"),
    ("missing-legacy-file", "remove", "README.md"),
    ("tampered-legacy-manifest", "append", "artifacts.sha256.json"),
    ("tampered-pr3-manifest", "append", "integrity/v1/pr3-additions.sha256.json"),
    ("missing-pr3-manifest", "remove", "integrity/v1/pr3-additions.sha256.json"),
    ("tampered-repair-manifest", "append", "integrity/v1/repair-files.sha256.json"),
    ("modified-repair-file", "append", "research/gateway_abuse_replay_v1/policy.py"),
    ("missing-repair-file", "remove", "research/gateway_abuse_replay_v1/policy.py"),
    ("tampered-policy", "append", "integrity/v1/policy.json"),
    ("missing-bootstrap", "remove", ".github/workflows/security-repair-v1.yml"),
    ("unexpected-file", "create", "INTEGRITY_UNAUTHORIZED_PROBE.tmp"),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def invoke(pin):
    process = subprocess.run(
        [sys.executable, "-B", "tools/integrity_v1.py", "--policy-sha256", pin],
        cwd=ROOT,
        capture_output=True,
    )
    return {
        "exit_code": process.returncode,
        "stdout_sha256": digest(process.stdout),
        "stderr_sha256": digest(process.stderr),
    }


def run(pin, out):
    results = []
    for name, action, relative in SPECS:
        path = ROOT / relative
        existed = path.is_file()
        original = path.read_bytes() if existed else None
        baseline = invoke(pin)
        applied = False
        try:
            if action == "append" and existed:
                path.write_bytes(original + b"INTEGRITY_MUTATION")
                applied = True
            elif action == "remove" and existed:
                path.unlink()
                applied = True
            elif action == "create" and not path.exists():
                path.write_bytes(b"unauthorized\n")
                applied = True
            mutated = invoke(pin) if applied else None
        finally:
            if original is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(original)
            elif path.exists():
                path.unlink()
        restored_bytes = path.is_file() and path.read_bytes() == original if original is not None else not path.exists()
        restored = invoke(pin)
        if baseline["exit_code"] != 0 or restored["exit_code"] != 0 or not restored_bytes:
            status = "CONTROL_BROKEN"
        elif not applied:
            status = "NOT_APPLIED"
        elif mutated is None or mutated["exit_code"] not in (0, 1, 2):
            status = "CRASHED"
        elif mutated["exit_code"] == 0:
            status = "SURVIVED"
        else:
            status = "KILLED"
        results.append({
            "mutation": name,
            "action": action,
            "path": relative,
            "status": status,
            "applied": applied,
            "restored": restored_bytes,
            "original_sha256": digest(original) if original is not None else None,
            "baseline": baseline,
            "mutated": mutated,
            "restored_control": restored,
        })
    statuses = ("KILLED", "SURVIVED", "NOT_APPLIED", "CRASHED", "CONTROL_BROKEN")
    counts = {status: sum(row["status"] == status for row in results) for status in statuses}
    report = {
        "schema": "guardian.integrity-mutations.v1",
        "population": len(results),
        "counts": counts,
        "results": results,
        "verdict": "PASS" if counts == {
            "KILLED": len(results), "SURVIVED": 0, "NOT_APPLIED": 0,
            "CRASHED": 0, "CONTROL_BROKEN": 0,
        } else "HOLD",
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(json.dumps(report, sort_keys=True, indent=2).encode("ascii") + b"\n")
    print(json.dumps({"verdict": report["verdict"], "counts": counts}, sort_keys=True))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    report = run(args.policy_sha256, args.out)
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
