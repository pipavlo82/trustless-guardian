"""No real network, tokens, signatures or OS actions: pure synthetic controls."""

import copy
import itertools
import json
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from research.gateway_abuse_replay_v0.adapter import mapped_events, mapped_source_seqs, rare_baseline
from research.gateway_abuse_replay_v0.cli import main
from research.gateway_abuse_replay_v0.detector import find
from research.gateway_abuse_replay_v0.detector_reference import find_reference
from research.gateway_abuse_replay_v0.fixtures import attack_fixture, benign_fixture, event, holdout_corpus
from research.gateway_abuse_replay_v0.metrics import evaluate_holdout
from research.gateway_abuse_replay_v0.mutation_audit import audit
from research.gateway_abuse_replay_v0.model import ReplayInputError, encode_events, read_events, strict_json, validate_events
from research.gateway_abuse_replay_v0.policy import evaluate
from research.gateway_abuse_replay_v0.policy_reference import evaluate_reference
from research.gateway_abuse_replay_v0.report import produce_report
from research.gateway_abuse_replay_v0.verifier import ReplayMismatch, recompute, verify_report
from research.rare_event_evidence_v0.verifier import verify_report as verify_rare

ROOT = Path(__file__).resolve().parents[1]


class ReplayTest(unittest.TestCase):
    def setUp(self):
        self.events, self.labels = attack_fixture()
        self.report = produce_report(self.events)

    def test_first_signal_precedes_first_simulated_denial(self):
        self.assertEqual((self.report["first_detection_seq"], self.report["first_simulated_prevention_seq"]), (4, 5))

    def test_first_signal_is_burst(self):
        self.assertEqual([x for x in self.report["findings"] if x["seq"] == 4],
                         [{"seq": 4, "kind": "ACTIVITY_BURST", "evidence_seqs": [2, 3, 4]}])

    def test_first_block_is_owner_admin_role_violation(self):
        self.assertEqual(self.report["decisions"][4],
                         {"seq": 5, "verdict": "DENY", "reason": "ADMIN_WALLET_ROLE_REQUIRED"})

    def test_first_prevention_is_simulated_not_enforcement(self):
        self.assertEqual(self.report["enforcement"], "NOT_EXECUTED")
        self.assertEqual(self.report["source_authentication"], "NOT_ESTABLISHED")
        self.assertEqual(self.report["classifications"][4]["status"], "BLOCKED_BY_AUTHORIZATION")

    def test_report_classification_distinguishes_all_four_states(self):
        statuses = {x["status"] for x in self.report["classifications"]}
        self.assertEqual(statuses, {"BLOCKED_BY_AUTHORIZATION", "DETECTED_ONLY", "NOT_DETECTED", "NOT_COVERED"})

    def test_unknown_external_observation_is_not_mislabeled_allow(self):
        self.assertEqual(self.report["decisions"][12]["verdict"], "NOT_COVERED")
        self.assertEqual(self.report["classifications"][12]["status"], "NOT_COVERED")
        self.assertNotIn(13, self.report["rare_event_v0"]["source_seqs"])

    def test_owner_admin_escalation_denied(self):
        self.assertEqual(evaluate(self.events[4])["verdict"], "DENY")

    def test_invalid_token_denied(self):
        e = dict(self.events[4], token_verified=False)
        self.assertEqual(evaluate(e)["reason"], "TOKEN_NOT_VERIFIED")

    def test_admin_role_wrong_wallet_denied(self):
        e = dict(self.events[4], token_role="ADMIN")
        self.assertEqual(evaluate(e)["reason"], "ADMIN_WALLET_ROLE_REQUIRED")

    def test_real_admin_simulated_allow(self):
        e = dict(self.events[4], token_role="ADMIN", wallet="wallet-admin")
        self.assertEqual(evaluate(e)["verdict"], "ALLOW")

    def test_empty_registry_proof_denied(self):
        self.assertEqual(evaluate(self.events[5])["reason"], "REGISTRY_PROOF_REQUIRED")

    def test_claimed_wallet_not_matching_registry_denied(self):
        e = dict(self.events[5], ownership_proof=True, agent="agent-probe", registry_owner="wallet-legit")
        self.assertEqual(evaluate(e)["reason"], "OWNER_WALLET_REQUIRED")

    def test_unapproved_mcp_destination_denied_even_as_admin(self):
        e = dict(self.events[7], token_role="ADMIN", wallet="wallet-admin", payload="SAFE")
        self.assertEqual(evaluate(e)["reason"], "MCP_DESTINATION_NOT_APPROVED")

    def test_unapproved_command_denied_even_as_service(self):
        self.assertEqual(evaluate(self.events[10])["reason"], "TOOL_PAYLOAD_NOT_ALLOWED")

    def test_simulated_valid_runner_test_allows_only_safe(self):
        e = dict(self.events[10], payload="SAFE")
        self.assertEqual(evaluate(e)["verdict"], "ALLOW")

    def test_pivot_to_telegram_denied(self):
        self.assertEqual(evaluate(self.events[11])["reason"], "SERVICE_IDENTITY_REQUIRED")

    def test_service_cross_system_wrong_scope_denied(self):
        e = dict(self.events[11], token_role="SERVICE", wallet="wallet-service")
        self.assertEqual(evaluate(e)["reason"], "SERVICE_IDENTITY_REQUIRED")

    def test_public_health_has_no_privileged_side_effect(self):
        self.assertEqual(evaluate(self.events[0]), {"verdict": "ALLOW", "reason": "PUBLIC_HEALTH_ONLY"})

    def test_second_path_exact_match(self):
        self.assertEqual(recompute(self.events), self.report)
        self.assertEqual(verify_report(self.events, self.report), "RECOMPUTE_MATCH_UNAUTHENTICATED_SYNTHETIC")

    def test_rare_event_v0_is_integrated(self):
        d = self.report["decisions"]
        result = self.report["rare_event_v0"]
        self.assertEqual(result["source_seqs"], mapped_source_seqs(self.events, d))
        self.assertEqual(verify_rare(rare_baseline(), mapped_events(self.events, d), result["report"]),
                         "RECOMPUTE_MATCH_UNAUTHENTICATED")

    def test_rare_v0_never_replaces_gateway_policy(self):
        self.assertEqual(self.report["decision"], "TRIAGE_AND_POLICY_SIMULATION_ONLY")
        self.assertEqual(self.report["rare_event_v0"]["report"]["decision"], "TRIAGE_ONLY")

    def test_benign_burst_is_measured_false_positive(self):
        e, labels = benign_fixture()
        self.assertEqual(labels, [])
        out = produce_report(e)
        self.assertEqual(out["first_detection_seq"], 23)
        self.assertIsNone(out["first_simulated_prevention_seq"])

    def test_truth_labels_never_part_of_detector_input(self):
        self.assertTrue(self.labels)
        self.assertNotIn("malicious", self.events[1])
        self.assertEqual(len(self.events), 14)

    def test_holdout_confusion_matrix_consistent(self):
        metrics = evaluate_holdout()
        conf = metrics["confusion_matrix"]
        self.assertEqual(sum(conf.values()), sum(len(e) for _, e, _ in holdout_corpus()))
        self.assertGreater(conf["FP"], 0)
        self.assertGreater(conf["FN"], 0)
        self.assertEqual(metrics["false_positive_rate"]["denominator"], conf["FP"] + conf["TN"])
        self.assertEqual(metrics["false_negative_rate"]["denominator"], conf["TP"] + conf["FN"])
        self.assertEqual(metrics["real_world_generalization"], "NOT_COVERED")

    def test_heldout_report_is_recomputed(self):
        for _, e, _ in holdout_corpus():
            self.assertEqual(produce_report(e), recompute(e))

    def test_parser_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_bytes(encode_events(self.events))
            self.assertEqual(read_events(path), self.events)

    def test_missing_field_refused_before_decision(self):
        e = copy.deepcopy(self.events)
        del e[0]["token_verified"]
        with self.assertRaises(ReplayInputError):
            produce_report(e)

    def test_added_unknown_field_refused(self):
        e = copy.deepcopy(self.events)
        e[0]["unexpected"] = "x"
        with self.assertRaises(ReplayInputError):
            produce_report(e)

    def test_live_origin_refused(self):
        e = copy.deepcopy(self.events)
        e[0]["origin"] = "live"
        with self.assertRaises(ReplayInputError):
            produce_report(e)

    def test_unknown_operation_refused(self):
        e = copy.deepcopy(self.events)
        e[0]["operation"] = "ARBITRARY_COMMAND"
        with self.assertRaises(ReplayInputError):
            produce_report(e)

    def test_real_wallet_address_not_admitted(self):
        e = copy.deepcopy(self.events)
        e[0]["wallet"] = "0xdeadbeef"
        with self.assertRaises(ReplayInputError):
            produce_report(e)

    def test_seq_reorder_refused(self):
        e = copy.deepcopy(self.events)
        e[0], e[1] = e[1], e[0]
        with self.assertRaises(ReplayInputError):
            produce_report(e)

    def test_tick_monotonicity_enforced(self):
        e = copy.deepcopy(self.events)
        e[4]["tick"] = e[3]["tick"]
        with self.assertRaises(ReplayInputError):
            produce_report(e)

    def test_boolean_vs_integer_strict(self):
        e = copy.deepcopy(self.events)
        e[3]["token_verified"] = 1
        with self.assertRaises(ReplayInputError):
            produce_report(e)

    def test_duplicate_json_keys_refused(self):
        with self.assertRaises(ValueError):
            strict_json('{"role":"owner","role":"admin"}')

    def test_nonfinite_json_refused(self):
        with self.assertRaises(ValueError):
            strict_json('{"tick":NaN}')

    def test_oversized_input_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "large.jsonl"
            p.write_bytes(b"x" * 1_000_001)
            with self.assertRaises(ReplayInputError):
                read_events(p)

    def test_empty_input_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "empty.jsonl"
            p.write_bytes(b"")
            with self.assertRaises(ReplayInputError):
                read_events(p)

    def test_report_tamper_refuted(self):
        e = copy.deepcopy(self.report)
        e["findings"][0]["kind"] = "FAKE_SUCCESS"
        with self.assertRaises(ReplayMismatch):
            verify_report(self.events, e)

    def test_report_escalation_refuted(self):
        e = copy.deepcopy(self.report)
        e["enforcement"] = "PRODUCTION_VERIFIED"
        with self.assertRaises(ReplayMismatch):
            verify_report(self.events, e)

    def test_report_recomputed_after_mutation_matches_but_not_authenticated(self):
        changed = copy.deepcopy(self.events)
        changed[4]["token_role"] = "ADMIN"
        changed[4]["wallet"] = "wallet-admin"
        new = produce_report(changed)
        self.assertEqual(verify_report(changed, new), "RECOMPUTE_MATCH_UNAUTHENTICATED_SYNTHETIC")
        self.assertEqual(new["source_authentication"], "NOT_ESTABLISHED")

    def test_cli_fixture_run_verify_evaluate(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            self.assertEqual(main(["fixtures", "--out", str(p / "fixtures")]), 0)
            f = str(p / "fixtures" / "attack.synthetic.jsonl")
            report = str(p / "report.json")
            self.assertEqual(main(["run", "--events", f, "--out", report]), 0)
            self.assertEqual(main(["verify", "--events", f, "--report", report]), 0)
            self.assertEqual(main(["evaluate", "--out", str(p / "metrics.json")]), 0)
            self.assertEqual(main(["mutations", "--out", str(p / "mutations.json")]), 0)
            self.assertTrue((p / "mutations.json").is_file())
            self.assertTrue((p / "metrics.json").is_file())

    def test_cli_refutes_corrupt_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "events.jsonl").write_bytes(encode_events(self.events))
            (p / "report.json").write_text('{"schema":"broken"}\n', encoding="utf-8")
            self.assertEqual(main(["verify", "--events", str(p / "events.jsonl"), "--report", str(p / "report.json")]), 1)

    def test_cli_rejects_missing_auth_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            mutated = copy.deepcopy(self.events)
            del mutated[3]["token_verified"]
            (p / "mutated.jsonl").write_bytes(b"".join(json.dumps(x).encode()+b"\n" for x in mutated))
            self.assertEqual(main(["run", "--events", str(p / "mutated.jsonl"), "--out", str(p / "report.json")]), 2)
            self.assertFalse((p / "report.json").exists())

    def test_physical_mutation_campaign_has_no_survivors(self):
        result = audit()
        self.assertEqual(result["population"], 14)
        self.assertEqual(result["counts"]["KILLED_REFUTED"], 13)
        self.assertEqual(result["counts"]["KILLED_INPUT_REJECTED"], 1)
        self.assertEqual(result["counts"]["SURVIVED"], 0)
        self.assertEqual(result["counts"]["NOT_APPLIED"], 0)
        self.assertEqual(result["counts"]["CONTROL_BROKEN"], 0)
        self.assertEqual(result["verdict"], "CONTROLLED_NEGATIVES_PASS")

    def test_physical_mutation_controls(self):
        # Standalone physical controls: source unchanged, mutation applied, restore.
        specs = [
            (4, "token_role", "ADMIN"), (4, "wallet", "wallet-admin"),
            (5, "ownership_proof", True), (7, "destination", "APPROVED"),
            (10, "payload", "SAFE"), (11, "token_verified", False),
            (2, "tick", 30), (9, "principal", "service"),
        ]
        baseline = encode_events(self.events)
        for index, field, value in specs:
            changed = copy.deepcopy(self.events)
            changed[index][field] = value
            self.assertNotEqual(changed, self.events)
            try:
                validate_events(changed)
            except ReplayInputError:
                # Invalid source is REJECTED before scoring, also a killed control.
                pass
            else:
                self.assertNotEqual(produce_report(changed), self.report)
                with self.assertRaises(ReplayMismatch):
                    verify_report(changed, self.report)
            self.assertEqual(encode_events(self.events), baseline)

    def test_independent_assembly_detects_corrupt_producer(self):
        # A matching parser/digest must not conceal a corrupted report assembler.
        with patch("research.gateway_abuse_replay_v0.report.assemble", return_value={"decision": "PRODUCTION_VERIFIED"}):
            broken = produce_report(self.events)
        with self.assertRaises(ReplayMismatch):
            verify_report(self.events, broken)

    def test_report_field_mutation_controls(self):
        edits = [
            ("finding_count", -1), ("event_count", 1), ("first_detection_seq", None),
            ("first_simulated_prevention_seq", None), ("policy_profile", "unsafe"),
            ("events_sha256", "0" * 64), ("scope", "PRODUCTION"),
        ]
        for field, value in edits:
            changed = copy.deepcopy(self.report)
            changed[field] = value
            with self.assertRaises(ReplayMismatch):
                verify_report(self.events, changed)

    def test_reference_policy_exhaustive_grid(self):
        template = self.events[4]
        for op, role, wallet, token, payload, dest, proof in itertools.product(
            ["ADMIN_WRITE", "REGISTER_AGENT", "REGISTER_MCP", "RUN_TOOL", "TELEGRAM_CALL", "SKILL_TEST"],
            ["ADMIN", "OWNER", "SERVICE", "ANON"],
            ["wallet-admin", "wallet-probe", "wallet-service", "wallet-telegram"],
            [False, True], ["SAFE", "UNSAFE_COMMAND"], ["APPROVED", "EXTERNAL"], [False, True]
        ):
            e = dict(template, operation=op, token_role=role, wallet=wallet,
                     token_verified=token, payload=payload, destination=dest, ownership_proof=proof)
            self.assertEqual(evaluate(e), evaluate_reference(e))

    def test_reference_detector_seeded_replays(self):
        for seed in range(20):
            rng = random.Random(seed)
            events = []
            for i in range(1, 60):
                kw = dict(
                    principal=rng.choice(["probe", "legit", "service", "telegram"]),
                    wallet=rng.choice(["wallet-probe", "wallet-legit", "wallet-admin", "wallet-service", "wallet-telegram"]),
                    role=rng.choice(["OWNER", "ADMIN", "SERVICE", "ANON"]),
                    verified=rng.choice([False, True]),
                    operation=rng.choice(["SKILL_TEST", "CREATE_SKILL", "MCP_CALL", "RUN_TOOL", "TELEGRAM_CALL", "REGISTER_AGENT"]),
                    service=rng.choice(["GATEWAY", "MCP", "RUNNER", "TELEGRAM"]),
                    destination=rng.choice(["INTERNAL", "APPROVED", "EXTERNAL", "PRIVATE_LAN"]),
                    payload=rng.choice(["SAFE", "UNSAFE_COMMAND", "DATA_EXPORT"]),
                    proof=rng.choice([False, True]),
                )
                events.append(event(i, i * 2, **kw))
            self.assertEqual(find(events), find_reference(events))
            self.assertEqual(produce_report(events), recompute(events))

    def test_frozen_synthetic_evidence_self_consistent(self):
        expected = ROOT / "research" / "gateway_abuse_replay_v0" / "SYNTHETIC_EVIDENCE.json"
        from research.gateway_abuse_replay_v0.model import canonical_bytes
        evidence = {
            "schema": "guardian.gateway-abuse-evidence.v0",
            "scope": "SYNTHETIC_ONLY_NO_PRODUCTION_CLAIM",
            "attack_replay": produce_report(attack_fixture()[0]),
            "holdout": evaluate_holdout(),
            "mutations": audit(),
        }
        self.assertEqual(expected.read_bytes(), canonical_bytes(evidence) + b"\n")


if __name__ == "__main__":
    unittest.main()
