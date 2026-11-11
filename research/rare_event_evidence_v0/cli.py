"""Read-only detector/second-path verifier CLI. Exit 0 match, 1 mismatch, 2 input error."""

import argparse
import sys
from pathlib import Path

from .detector import produce_report
from .fixtures import write_fixtures
from .model import InputError, canonical_bytes, read_events, strict_json
from .verifier import ReportMismatch, verify_report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Synthetic rare-event evidence, research only")
    sub = parser.add_subparsers(dest="cmd", required=True)
    fixtures = sub.add_parser("fixtures")
    fixtures.add_argument("--out", required=True)
    detector = sub.add_parser("detect")
    verifier = sub.add_parser("verify")
    for command in (detector, verifier):
        command.add_argument("--baseline", required=True)
        command.add_argument("--events", required=True)
    detector.add_argument("--out", required=True)
    verifier.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "fixtures":
            write_fixtures(args.out)
            print("SYNTHETIC_FIXTURES_WRITTEN")
        else:
            baseline = read_events(args.baseline, baseline=True)
            events = read_events(args.events)
            if args.cmd == "detect":
                report = produce_report(baseline, events)
                Path(args.out).write_bytes(canonical_bytes(report) + b"\n")
                print(f"TRIAGE_ONLY findings={report['finding_count']}")
            else:
                report_file = Path(args.report)
                if report_file.stat().st_size > 5_000_000:
                    raise InputError("report exceeds byte limit")
                report = strict_json(report_file.read_text(encoding="utf-8"))
                print(verify_report(baseline, events, report))
        return 0
    except ReportMismatch as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (InputError, OSError, UnicodeError, ValueError) as exc:
        print(f"INPUT_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
