"""Synthetic regression, independent recompute and physical negative controls."""

import copy
import json
import random
import tempfile
import unittest
from pathlib import Path

from research.rare_event_evidence_v0.cli import main
from research.rare_event_evidence_v0.detector import produce_report
from research.rare_event_evidence_v0.fixtures import event, fixture_sets, write_fixtures
from research.rare_event_evidence_v0.model import (
    InputError, canonical_bytes, digest, encode_events, read_events, strict_json,
)
from research.rare_event_evidence_v0.verifier import ReportMismatch, recompute, verify_report


class RareEventEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = fixture_sets()
        cls.baseline = cls.fixtures["baseline.jsonl"]
        cls.benign = cls.fixtures["benign.jsonl"]
        cls.anomaly = cls.fixtures["anomaly.jsonl"]

    def test_benign_has_no_findings(self):
        report = produce_report(self.baseline, self.benign)
        self.assertEqual(report["finding_count"], 0)
        self.assertEqual(report["decision"], "TRIAGE_ONLY")

    def test_anomaly_classification(self):
        kinds = {(f["seq"], f["kind"]) for f in produce_report(self.baseline, self.anomaly)["findings"]}
        self.assertIn((4, "DENIAL_BURST"), kinds)
        self.assertIn((5, "DENY_ALLOW_REVISION_CHANGE"), kinds)
        self.assertIn((6, "DENY_ALLOW_REVISION_CHANGE"), kinds)
        self.assertIn((7, "RECOVERY_OBSERVED"), kinds)
        self.assertIn((1, "RARE_PAIR"), kinds)

    def test_readonly_verifier_matches(self):
        report = produce_report(self.baseline, self.anomaly)
        self.assertEqual(verify_report(self.baseline, self.anomaly, report), "RECOMPUTE_MATCH_UNAUTHENTICATED")

    def test_reference_second_path_is_distinct_callable(self):
        self.assertEqual(recompute(self.baseline, self.anomaly), produce_report(self.baseline, self.anomaly))

    def test_deterministic_bytes(self):
        first = canonical_bytes(produce_report(self.baseline, self.anomaly))
        second = canonical_bytes(produce_report(self.baseline, self.anomaly))
        self.assertEqual(first, second)
        self.assertEqual(digest(self.anomaly), digest(copy.deepcopy(self.anomaly)))

    def test_no_misleading_security_verdict(self):
        report = produce_report(self.baseline, self.anomaly)
        self.assertNotIn("VERIFIED", json.dumps(report))
        self.assertNotIn("AUTHORIZED", json.dumps(report))

    def test_mutant_event_action_refuted(self):
        report = produce_report(self.baseline, self.anomaly)
        mutant = copy.deepcopy(self.anomaly)
        mutant[0]["action"] = "DELETE"
        with self.assertRaises(ReportMismatch):
            verify_report(self.baseline, mutant, report)

    def test_mutant_baseline_refuted(self):
        report = produce_report(self.baseline, self.anomaly)
        mutant = copy.deepcopy(self.baseline)
        mutant[0]["outcome"] = "DENY"
        with self.assertRaises(ReportMismatch):
            verify_report(mutant, self.anomaly, report)

    def test_mutant_findings_removed_refuted(self):
        report = produce_report(self.baseline, self.anomaly)
        report["findings"].pop()
        with self.assertRaises(ReportMismatch):
            verify_report(self.baseline, self.anomaly, report)

    def test_mutant_finding_kind_refuted(self):
        report = produce_report(self.baseline, self.anomaly)
        report["findings"][0]["kind"] = "INVENTED_PASS"
        with self.assertRaises(ReportMismatch):
            verify_report(self.baseline, self.anomaly, report)

    def test_mutant_evidence_reference_refuted(self):
        report = produce_report(self.baseline, self.anomaly)
        report["findings"][0]["evidence_seqs"] = [999]
        with self.assertRaises(ReportMismatch):
            verify_report(self.baseline, self.anomaly, report)

    def test_mutant_scope_refuted(self):
        report = produce_report(self.baseline, self.anomaly)
        report["decision"] = "AUTHORIZED"
        with self.assertRaises(ReportMismatch):
            verify_report(self.baseline, self.anomaly, report)

    def test_mutant_reordered_events_refuted(self):
        report = produce_report(self.baseline, self.anomaly)
        mutant = copy.deepcopy(self.anomaly)
        mutant[0], mutant[1] = mutant[1], mutant[0]
        with self.assertRaises(ReportMismatch):
            verify_report(self.baseline, mutant, report)

    def test_mutant_inserted_event_refuted(self):
        report = produce_report(self.baseline, self.anomaly)
        mutant = copy.deepcopy(self.anomaly) + [event(8)]
        with self.assertRaises(ReportMismatch):
            verify_report(self.baseline, mutant, report)

    def test_strict_rejects_duplicate_key(self):
        with self.assertRaises(InputError):
            strict_json('{"seq":1,"seq":1}')

    def test_strict_rejects_nan(self):
        with self.assertRaises(InputError):
            strict_json('{"value":NaN}')

    def test_strict_rejects_extra_field(self):
        item = event(1)
        item["unknown"] = "anything"
        with self.assertRaises(InputError):
            encode_events([item])

    def test_strict_rejects_bool_sequence(self):
        item = event(1)
        item["seq"] = True
        with self.assertRaises(InputError):
            encode_events([item])

    def test_strict_rejects_bool_revision(self):
        item = event(1)
        item["policy_revision"] = True
        with self.assertRaises(InputError):
            encode_events([item])

    def test_strict_rejects_non_synthetic(self):
        item = event(1)
        item["origin"] = "production"
        with self.assertRaises(InputError):
            encode_events([item])

    def test_strict_rejects_traversal_resource(self):
        item = event(1)
        item["resource"] = "../private/key"
        with self.assertRaises(InputError):
            encode_events([item])

    def test_strict_rejects_noncontiguous_seq(self):
        with self.assertRaises(InputError):
            encode_events([event(1), event(3)])

    def test_read_events_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            filename = Path(td) / "events.jsonl"
            filename.write_bytes(encode_events(self.anomaly))
            self.assertEqual(read_events(filename), self.anomaly)

    def test_read_events_rejects_short_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            filename = Path(td) / "baseline.jsonl"
            filename.write_bytes(encode_events(self.anomaly))
            with self.assertRaises(InputError):
                read_events(filename, baseline=True)

    def test_read_events_rejects_oversized_line(self):
        with tempfile.TemporaryDirectory() as td:
            filename = Path(td) / "bad.jsonl"
            filename.write_bytes(b" " * 2049 + b"\n")
            with self.assertRaises(InputError):
                read_events(filename)

    def test_cli_end_to_end_and_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self.assertEqual(main(["fixtures", "--out", str(base)]), 0)
            self.assertEqual(main(["detect", "--baseline", str(base / "baseline.jsonl"),
                                   "--events", str(base / "anomaly.jsonl"), "--out", str(base / "report.json")]), 0)
            args = ["verify", "--baseline", str(base / "baseline.jsonl"),
                    "--events", str(base / "anomaly.jsonl"), "--report", str(base / "report.json")]
            self.assertEqual(main(args), 0)
            report = json.loads((base / "report.json").read_text())
            report["findings"][0]["kind"] = "WRONG"
            (base / "report.json").write_bytes(canonical_bytes(report))
            self.assertEqual(main(args), 1)

    def test_distinct_population_random_replay(self):
        generator = random.Random(271828)
        for size in range(1, 90):
            events = [event(i, action=generator.choice(("READ", "WRITE", "POLICY_CHANGE", "DELETE")),
                            outcome=generator.choice(("ALLOW", "DENY", "RECOVERY_REQUIRED")),
                            agent=generator.choice(("agent-a", "agent-b")),
                            resource=generator.choice(("resource-a", "resource-b")),
                            policy_revision=generator.randrange(3)) for i in range(1, size + 1)]
            self.assertEqual(recompute(self.baseline, events), produce_report(self.baseline, events), f"size={size}")


if __name__ == "__main__":
    unittest.main()
