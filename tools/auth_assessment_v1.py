"""Independent, secret-free assessment runner for authentication v1."""

import argparse
import hashlib
from importlib import metadata
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("PyJWT", "cryptography", "siwe", "eth-account", "abnf")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EvidenceResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes.append({"test": test.id(), "status": "PASS"})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes.append({"test": test.id(), "status": "FAIL"})

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes.append({"test": test.id(), "status": "ERROR"})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes.append({"test": test.id(), "status": "SKIP", "reason": reason})


def run(out):
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests_auth_v1"), top_level_dir=str(ROOT))
    runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=1, resultclass=EvidenceResult)
    result = runner.run(suite)
    source_paths = sorted(
        list((ROOT / "research/auth_gateway_v1").glob("*.py"))
        + list((ROOT / "tests_auth_v1").glob("*.py"))
    )
    counts = {
        "PASS": sum(row["status"] == "PASS" for row in result.outcomes),
        "FAIL": sum(row["status"] == "FAIL" for row in result.outcomes),
        "ERROR": sum(row["status"] == "ERROR" for row in result.outcomes),
        "SKIP": sum(row["status"] == "SKIP" for row in result.outcomes),
    }
    report = {
        "schema": "guardian.independent-auth-assessment.v1",
        "scope": "LOCAL_DISPOSABLE_KEYS_AND_REGISTRIES_ONLY",
        "production_credentials_used": False,
        "optimized_python": not __debug__,
        "python": sys.version.split()[0],
        "dependencies": {name: metadata.version(name) for name in PACKAGES},
        "source_sha256": {
            path.relative_to(ROOT).as_posix(): digest(path) for path in source_paths
        },
        "counts": counts,
        "tests": sorted(result.outcomes, key=lambda row: row["test"]),
        "passed": result.wasSuccessful(),
        "production_ready": False,
        "verdict": "PASS" if result.wasSuccessful() else "HOLD",
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(json.dumps(report, sort_keys=True, indent=2).encode("ascii") + b"\n")
    print(json.dumps({"counts": counts, "verdict": report["verdict"]}, sort_keys=True))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    return 0 if run(args.out)["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
