"""Physical synthetic mutation controls with restoration; not attack resistance proof."""

import copy
import tempfile
from pathlib import Path

from research.rare_event_evidence_v0.model import canonical_bytes, digest

from .fixtures import attack_fixture
from .model import ReplayInputError, encode_events, read_events, read_report
from .report import produce_report
from .verifier import ReplayMismatch, verify_report


def audit():
    source, _ = attack_fixture()
    report = produce_report(source)
    original_input = encode_events(source)
    original_report = canonical_bytes(report) + b"\n"
    source_changes = [
        ("role", 4, "token_role", "ADMIN"),
        ("wallet", 4, "wallet", "wallet-admin"),
        ("signature-flag", 1, "token_verified", False),
        ("ownership", 5, "ownership_proof", True),
        ("registry-owner", 5, "registry_owner", "wallet-legit"),
        ("command-class", 10, "payload", "SAFE"),
        ("mcp-target", 7, "destination", "APPROVED"),
        ("time-rewind", 4, "tick", 12),
        ("principal-switch", 3, "principal", "legit"),
    ]
    report_changes = [
        ("verdict-escalation", "enforcement", "ENFORCED"),
        ("dropped-signal", "findings", report["findings"][1:]),
        ("missing-authorization", "decisions", report["decisions"][1:]),
        ("invented-coverage", "source_authentication", "ESTABLISHED"),
        ("changed-count", "event_count", 15),
    ]
    rows = []
    with tempfile.TemporaryDirectory() as root:
        folder = Path(root)
        input_file = folder / "events.jsonl"
        report_file = folder / "report.json"
        input_file.write_bytes(original_input)
        report_file.write_bytes(original_report)
        for name, index, field, value in source_changes:
            mutant = copy.deepcopy(source)
            mutant[index][field] = value
            mutant_bytes = b"".join(canonical_bytes(event) + b"\n" for event in mutant)
            input_file.write_bytes(mutant_bytes)
            applied = mutant_bytes != original_input
            status = "SURVIVED"
            if not applied:
                status = "NOT_APPLIED"
            else:
                try:
                    parsed = read_events(input_file)
                    verify_report(parsed, read_report(report_file))
                except ReplayInputError:
                    status = "KILLED_INPUT_REJECTED"
                except ReplayMismatch:
                    status = "KILLED_REFUTED"
            input_file.write_bytes(original_input)
            restored = input_file.read_bytes() == original_input and report_file.read_bytes() == original_report
            if not restored:
                status = "CONTROL_BROKEN"
            rows.append({"mutation": name, "domain": "event", "status": status, "applied": applied, "restored": restored,
                         "original_sha256": digest(source), "mutant_sha256": digest(mutant)})
        for name, field, value in report_changes:
            mutant = copy.deepcopy(report)
            mutant[field] = copy.deepcopy(value)
            mutant_bytes = canonical_bytes(mutant) + b"\n"
            report_file.write_bytes(mutant_bytes)
            applied = mutant_bytes != original_report
            status = "SURVIVED"
            if not applied:
                status = "NOT_APPLIED"
            else:
                try:
                    verify_report(read_events(input_file), read_report(report_file))
                except ReplayMismatch:
                    status = "KILLED_REFUTED"
            report_file.write_bytes(original_report)
            restored = input_file.read_bytes() == original_input and report_file.read_bytes() == original_report
            if not restored:
                status = "CONTROL_BROKEN"
            rows.append({"mutation": name, "domain": "report", "status": status, "applied": applied, "restored": restored,
                         "original_sha256": digest(report), "mutant_sha256": digest(mutant)})
    counts = {status: sum(item["status"] == status for item in rows) for status in
              ("KILLED_REFUTED", "KILLED_INPUT_REJECTED", "SURVIVED", "NOT_APPLIED", "CONTROL_BROKEN")}
    return {"schema": "guardian.gateway-abuse-mutation-audit.v0", "scope": "SYNTHETIC_PHYSICAL_MUTANTS_ONLY",
            "population": len(rows), "counts": counts, "results": rows,
            "verdict": "CONTROLLED_NEGATIVES_PASS" if (counts["KILLED_REFUTED"] + counts["KILLED_INPUT_REJECTED"] == len(rows)
                                                        and not counts["CONTROL_BROKEN"]) else "HOLD"}
