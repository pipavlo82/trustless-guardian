"""Offline synthetic replay and second-path verifier. Never contacts services."""

import argparse
import sys
from pathlib import Path

from research.rare_event_evidence_v0.model import canonical_bytes

from .fixtures import write_fixtures
from .metrics import evaluate_holdout
from .mutation_audit import audit
from .model import ReplayInputError, read_events, read_report
from .report import produce_report
from .verifier import ReplayMismatch, verify_report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Synthetic gateway-abuse replay; no live calls")
    subs = parser.add_subparsers(dest="cmd", required=True)
    fixtures = subs.add_parser("fixtures")
    fixtures.add_argument("--out", required=True)
    detector = subs.add_parser("run")
    verifier = subs.add_parser("verify")
    for command in (detector, verifier):
        command.add_argument("--events", required=True)
    detector.add_argument("--out", required=True)
    verifier.add_argument("--report", required=True)
    metrics = subs.add_parser("evaluate")
    metrics.add_argument("--out", required=True)
    mutations = subs.add_parser("mutations")
    mutations.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "fixtures":
            write_fixtures(args.out)
            print("SYNTHETIC_FIXTURES_WRITTEN")
        elif args.cmd == "mutations":
            result = audit()
            Path(args.out).write_bytes(canonical_bytes(result) + b"\n")
            print(f"SYNTHETIC_MUTATIONS {result['counts']}")
            return 0 if result["verdict"] == "CONTROLLED_NEGATIVES_PASS" else 1
        elif args.cmd == "evaluate":
            Path(args.out).write_bytes(canonical_bytes(evaluate_holdout()) + b"\n")
            print("SYNTHETIC_HOLDOUT_MEASURED")
        else:
            events = read_events(args.events)
            if args.cmd == "run":
                report = produce_report(events)
                Path(args.out).write_bytes(canonical_bytes(report) + b"\n")
                print(f"SYNTHETIC_ONLY detected={report['first_detection_seq']} simulated_block={report['first_simulated_prevention_seq']}")
            else:
                print(verify_report(events, read_report(args.report)))
        return 0
    except ReplayMismatch as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (ReplayInputError, OSError, UnicodeError, ValueError) as exc:
        print(f"INPUT_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
