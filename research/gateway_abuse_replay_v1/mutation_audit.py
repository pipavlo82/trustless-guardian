"""Physical input/report mutation controls with byte-exact restoration."""

import copy
import tempfile
from pathlib import Path

from research.rare_event_evidence_v0.model import canonical_bytes, digest

from .fixtures import functional_trace
from .model import ReplayInputError, encode_events, read_events, read_report
from .report import produce_report
from .verifier import ReplayMismatch, verify_report


def _classify(call, baseline_ok, applied, restored):
    if not baseline_ok or not restored:
        return "CONTROL_BROKEN"
    if not applied:
        return "NOT_APPLIED"
    try:
        call()
    except (ReplayMismatch, ReplayInputError):
        return "KILLED"
    except Exception:
        return "CRASHED"
    return "SURVIVED"


def audit():
    source = functional_trace(); report = produce_report(source)
    original_input = encode_events(source); original_report = canonical_bytes(report) + b"\n"
    event_mutations = [
        ("token-subject", 1, "token_subject", "owner-b"),
        ("token-wallet", 1, "token_wallet", "wallet-b"),
        ("role-confusion", 2, "token_role", "OWNER"),
        ("admin-wallet", 2, "wallet", "wallet-a"),
        ("resource-owner", 3, "claimed_owner", "owner-b"),
        ("unsafe-tool", 3, "payload", "UNSAFE_COMMAND"),
        ("subject-admin-confusion", 4, "request_subject", "admin"),
        ("proof-removal", 1, "ownership_proof", False),
        ("tick-rewind", 4, "tick", 30),
    ]
    report_mutations = [
        ("enforcement-escalation", "enforcement", "VERIFIED"),
        ("source-authentication", "source_authentication", "ESTABLISHED"),
        ("decision-removal", "decisions", report["decisions"][1:]),
        ("finding-removal", "findings", []),
        ("event-count", "event_count", 999),
        ("policy-profile", "policy_profile", "unreviewed"),
    ]
    results = []
    with tempfile.TemporaryDirectory() as root:
        input_path = Path(root) / "events.jsonl"; report_path = Path(root) / "report.json"
        input_path.write_bytes(original_input); report_path.write_bytes(original_report)
        for name, index, field, value in event_mutations:
            baseline_ok = verify_report(read_events(input_path), read_report(report_path)).startswith("RECOMPUTE_MATCH")
            mutant = copy.deepcopy(source); mutant[index][field] = value
            raw = b"".join(canonical_bytes(event) + b"\n" for event in mutant); input_path.write_bytes(raw)
            applied = raw != original_input
            input_path.write_bytes(original_input)
            restored = input_path.read_bytes() == original_input and report_path.read_bytes() == original_report
            input_path.write_bytes(raw)
            status = _classify(lambda: verify_report(read_events(input_path), read_report(report_path)), baseline_ok, applied, restored)
            input_path.write_bytes(original_input)
            results.append({"mutation": name, "domain": "event", "status": status, "applied": applied,
                            "restored": input_path.read_bytes() == original_input, "original_sha256": digest(source), "mutant_sha256": digest(mutant)})
        for name, field, value in report_mutations:
            baseline_ok = verify_report(read_events(input_path), read_report(report_path)).startswith("RECOMPUTE_MATCH")
            mutant = copy.deepcopy(report); mutant[field] = copy.deepcopy(value); raw = canonical_bytes(mutant) + b"\n"
            report_path.write_bytes(raw); applied = raw != original_report
            report_path.write_bytes(original_report)
            restored = input_path.read_bytes() == original_input and report_path.read_bytes() == original_report
            report_path.write_bytes(raw)
            status = _classify(lambda: verify_report(read_events(input_path), read_report(report_path)), baseline_ok, applied, restored)
            report_path.write_bytes(original_report)
            results.append({"mutation": name, "domain": "report", "status": status, "applied": applied,
                            "restored": report_path.read_bytes() == original_report, "original_sha256": digest(report), "mutant_sha256": digest(mutant)})
    counts = {name: sum(row["status"] == name for row in results) for name in ("KILLED", "SURVIVED", "NOT_APPLIED", "CRASHED", "CONTROL_BROKEN")}
    return {"schema": "guardian.gateway-abuse-mutation-audit.v1", "population": len(results), "counts": counts,
            "results": results, "verdict": "PASS" if counts == {"KILLED": len(results), "SURVIVED": 0, "NOT_APPLIED": 0, "CRASHED": 0, "CONTROL_BROKEN": 0} else "HOLD"}

