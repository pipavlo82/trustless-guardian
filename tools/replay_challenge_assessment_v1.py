"""Secret-free independent assessment for replay, challenge, and receipt boundaries."""

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

    def _add(self, test, status, reason=None):
        value = {"test": test.id(), "status": status}
        if reason is not None:
            value["reason"] = reason
        self.outcomes.append(value)

    def addSuccess(self, test):
        super().addSuccess(test)
        self._add(test, "PASS")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._add(test, "FAIL")

    def addError(self, test, err):
        super().addError(test, err)
        self._add(test, "ERROR")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._add(test, "SKIP", reason)


def run(out):
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests_replay_v1"), top_level_dir=str(ROOT))
    runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=1, resultclass=EvidenceResult)
    result = runner.run(suite)
    source_paths = sorted(
        list((ROOT / "research/replay_challenge_v1").glob("*.py"))
        + list((ROOT / "tests_replay_v1").glob("*.py"))
        + [ROOT / "research/linux_isolated_worker_v2/pilot.py"]
    )
    counts = {
        name: sum(row["status"] == name for row in result.outcomes)
        for name in ("PASS", "FAIL", "ERROR", "SKIP")
    }
    report = {
        "schema": "guardian.replay-challenge-assessment.v1",
        "scope": "LOCAL_SYNTHETIC_KEYS_REQUESTS_AND_STATE_ONLY",
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
    out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii", newline="\n")
    print(json.dumps({"counts": counts, "verdict": report["verdict"]}, sort_keys=True))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    return 0 if run(args.out)["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
