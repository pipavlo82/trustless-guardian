"""Machine-readable inherited Guardian regression assessment."""

import argparse
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


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
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=1, resultclass=EvidenceResult)
    result = runner.run(suite)
    counts = {
        name: sum(row["status"] == name for row in result.outcomes)
        for name in ("PASS", "FAIL", "ERROR", "SKIP")
    }
    report = {
        "schema": "guardian.inherited-regression-assessment.v1",
        "optimized_python": not __debug__,
        "python": sys.version.split()[0],
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
