"""Physical negative controls for the PR #5 layered integrity policy."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SPECS = (
    ("modified-frozen-source", "append", "README.md"),
    ("missing-frozen-source", "remove", "README.md"),
    ("tampered-original-inventory", "append", "artifacts.sha256.json"),
    ("tampered-pr4-frozen-manifest", "append", "integrity/v2/pr4-base.sha256.json"),
    ("missing-pr4-frozen-manifest", "remove", "integrity/v2/pr4-base.sha256.json"),
    ("tampered-authorized-manifest", "append", "integrity/v2/auth-linux-files.sha256.json"),
    ("modified-auth-source", "append", "research/auth_gateway_v1/jwt_auth.py"),
    ("missing-auth-source", "remove", "research/auth_gateway_v1/jwt_auth.py"),
    ("modified-dependency-lock", "append", "requirements-auth-v1.txt"),
    ("tampered-policy", "append", "integrity/v2/policy.json"),
    ("missing-bootstrap", "remove", ".github/workflows/auth-linux-v1.yml"),
    ("unexpected-file", "create", "INTEGRITY_V2_UNAUTHORIZED.tmp"),
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def invoke(pin):
    process = subprocess.run(
        [sys.executable, "-B", "tools/integrity_v2.py", "--policy-sha256", pin],
        cwd=ROOT,
        capture_output=True,
    )
    return {
        "exit_code": process.returncode,
        "stdout_sha256": sha(process.stdout),
        "stderr_sha256": sha(process.stderr),
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
                path.write_bytes(original + b"INTEGRITY_V2_MUTATION")
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
        restored_bytes = path.read_bytes() == original if original is not None else not path.exists()
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
            "original_sha256": sha(original) if original is not None else None,
            "baseline": baseline,
            "mutated": mutated,
            "restored_control": restored,
        })
    statuses = ("KILLED", "SURVIVED", "NOT_APPLIED", "CRASHED", "CONTROL_BROKEN")
    counts = {status: sum(row["status"] == status for row in results) for status in statuses}
    passed = counts == {
        "KILLED": len(results),
        "SURVIVED": 0,
        "NOT_APPLIED": 0,
        "CRASHED": 0,
        "CONTROL_BROKEN": 0,
    }
    report = {
        "schema": "guardian.integrity-mutations.v2",
        "population": len(results),
        "counts": counts,
        "results": results,
        "verdict": "PASS" if passed else "HOLD",
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(json.dumps(report, sort_keys=True, indent=2).encode("ascii") + b"\n")
    print(json.dumps({"counts": counts, "verdict": report["verdict"]}, sort_keys=True))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    return 0 if run(args.policy_sha256, args.out)["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
