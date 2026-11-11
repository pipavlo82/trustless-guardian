"""Offline v1 synthetic replay. No service or network access."""

import argparse
import sys
from pathlib import Path

from research.rare_event_evidence_v0.model import canonical_bytes

from .fixtures import functional_trace
from .metrics import evaluate_holdout
from .model import ReplayInputError, encode_events, read_events, read_report
from .mutation_audit import audit
from .report import produce_report
from .verifier import ReplayMismatch, verify_report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Synthetic gateway repair v1; never live")
    sub = parser.add_subparsers(dest="command", required=True)
    fixture = sub.add_parser("fixture"); fixture.add_argument("--out", required=True)
    run = sub.add_parser("run"); run.add_argument("--events", required=True); run.add_argument("--out", required=True)
    verify = sub.add_parser("verify"); verify.add_argument("--events", required=True); verify.add_argument("--report", required=True)
    evaluate = sub.add_parser("evaluate"); evaluate.add_argument("--out", required=True)
    mutations = sub.add_parser("mutations"); mutations.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "fixture":
            Path(args.out).write_bytes(encode_events(functional_trace())); print("SYNTHETIC_V1_FIXTURE_WRITTEN")
        elif args.command == "run":
            value = produce_report(read_events(args.events)); Path(args.out).write_bytes(canonical_bytes(value) + b"\n"); print("SYNTHETIC_V1_REPORT_WRITTEN")
        elif args.command == "verify":
            print(verify_report(read_events(args.events), read_report(args.report)))
        elif args.command == "evaluate":
            Path(args.out).write_bytes(canonical_bytes(evaluate_holdout()) + b"\n"); print("SYNTHETIC_V1_HOLDOUT_MEASURED")
        else:
            value = audit(); Path(args.out).write_bytes(canonical_bytes(value) + b"\n"); print(f"SYNTHETIC_V1_MUTATIONS {value['counts']}")
            return 0 if value["verdict"] == "PASS" else 1
        return 0
    except ReplayMismatch as exc:
        print(str(exc), file=sys.stderr); return 1
    except (ReplayInputError, OSError, ValueError) as exc:
        print(f"INPUT_ERROR: {exc}", file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())

