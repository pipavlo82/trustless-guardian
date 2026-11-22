import ast
import copy
import inspect
import itertools
import random
import tempfile
import unittest
from pathlib import Path

from research.gateway_abuse_replay_v1.cli import main
from research.gateway_abuse_replay_v1.detector import find
from research.gateway_abuse_replay_v1.fixtures import admin, event, functional_trace, health, service
from research.gateway_abuse_replay_v1.heldout import corpus
from research.gateway_abuse_replay_v1.metrics import evaluate_holdout
from research.gateway_abuse_replay_v1.model import ReplayInputError, encode_events, read_events, validate_events
from research.gateway_abuse_replay_v1.mutation_audit import audit
from research.gateway_abuse_replay_v1.policy import evaluate
from research.gateway_abuse_replay_v1.report import produce_report
from research.gateway_abuse_replay_v1.verifier import ReplayMismatch, recompute, reference_decision, reference_find, verify_report
from tools.audit_v0_bindings import audit as audit_v0_bindings


class GatewayRepairV1(unittest.TestCase):
    def setUp(self):
        self.events = functional_trace(); self.report = produce_report(self.events)

    def test_valid_bindings_allow(self):
        for row in (event(1, 1), admin(1, 1), admin(1, 1, "REGISTER_MCP"), service(1, 1), service(1, 1, "MCP_CALL"), service(1, 1, "TELEGRAM_CALL"), health(1, 1)):
            self.assertEqual(evaluate(row)["verdict"], "ALLOW")

    def test_v0_admin_subject_confusion_fixed(self):
        row = event(1, 1, subject="attacker", wallet="wallet-admin", token_wallet="wallet-admin", role="ADMIN", operation="ADMIN_WRITE")
        self.assertEqual(evaluate(row), {"verdict": "DENY", "reason": "SUBJECT_WALLET_MISMATCH"})

    def test_independent_v0_binding_defects_reproduce(self):
        result = audit_v0_bindings()
        self.assertTrue(result["reproduced"])
        self.assertEqual(len(result["cases"]), 4)
        self.assertTrue(all(row["v0_policy"]["verdict"] == "ALLOW" and not row["v0_detector"] for row in result["cases"]))

    def test_token_subject_binding(self):
        self.assertEqual(evaluate(event(1, 1, token_subject="owner-b"))["reason"], "TOKEN_SUBJECT_MISMATCH")

    def test_token_wallet_binding(self):
        self.assertEqual(evaluate(event(1, 1, token_wallet="wallet-b"))["reason"], "TOKEN_WALLET_MISMATCH")

    def test_resource_owner_binding(self):
        self.assertEqual(evaluate(event(1, 1, agent="agent-b", claimed_owner="owner-a"))["reason"], "RESOURCE_OWNER_MISMATCH")

    def test_service_subject_binding(self):
        row = service(1, 1); row["request_subject"] = row["token_subject"] = "svc-mcp"; row["wallet"] = row["token_wallet"] = "wallet-mcp"
        self.assertEqual(evaluate(row)["reason"], "SERVICE_SUBJECT_ROLE_WALLET_REQUIRED")

    def test_admin_request_cannot_cross_service_boundary(self):
        row = admin(1, 1); row["service"] = "MCP"
        self.assertEqual(evaluate(row), {"verdict": "DENY", "reason": "ADMIN_REQUEST_SCOPE_DENIED"})

    def test_tool_request_cannot_cross_service_boundary(self):
        row = service(1, 1, "RUN_TOOL"); row["service"] = "GATEWAY"
        self.assertEqual(evaluate(row), {"verdict": "DENY", "reason": "SERVICE_SUBJECT_ROLE_WALLET_REQUIRED"})

    def test_public_health_exact_shape(self):
        row = health(1, 1); row["payload"] = "UNSAFE_COMMAND"
        self.assertEqual(evaluate(row), {"verdict": "DENY", "reason": "PUBLIC_HEALTH_SHAPE"})

    def test_registration_requires_proof_and_owner(self):
        row = event(1, 1, operation="REGISTER_AGENT", proof=False)
        self.assertEqual(evaluate(row)["reason"], "REGISTRY_PROOF_REQUIRED")
        row = event(1, 1, operation="REGISTER_AGENT", agent="agent-b", claimed_owner="owner-b")
        self.assertEqual(evaluate(row)["reason"], "RESOURCE_OWNER_MISMATCH")

    def test_mcp_destination_and_tool_payload(self):
        row = service(1, 1, "MCP_CALL"); row["destination"] = "PRIVATE_LAN"
        self.assertEqual(evaluate(row)["reason"], "DESTINATION_OUTSIDE_POLICY")
        row = service(1, 1, "RUN_TOOL"); row["payload"] = "UNSAFE_COMMAND"
        self.assertEqual(evaluate(row)["reason"], "TOOL_PAYLOAD_NOT_ALLOWED")

    def test_detection_is_not_authorization(self):
        rows = [admin(1, 1), admin(2, 2, "CREATE_SKILL"), admin(3, 3, "ADMIN_WRITE", agent="agent-b", owner="owner-b")]
        self.assertTrue(find(rows)); self.assertTrue(all(evaluate(row)["verdict"] == "ALLOW" for row in rows))
        tree = ast.parse(inspect.getsource(__import__("research.gateway_abuse_replay_v1.policy", fromlist=["evaluate"])))
        imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertFalse(any("detector" in name for name in imports))

    def test_detector_covers_requested_classes(self):
        kinds = set()
        for _, rows, positives in corpus():
            if positives: kinds.update(row["kind"] for row in find(rows))
        required = {"ROLE_CONFUSION", "SUBJECT_BINDING_MISMATCH", "WALLET_BINDING_MISMATCH", "RESOURCE_BINDING_MISMATCH",
                    "UNAUTHORIZED_REGISTRATION", "UNAPPROVED_MCP_TARGET", "HIGH_RISK_TOOL_INTENT", "CROSS_SERVICE_IDENTITY_INTENT"}
        self.assertTrue(required <= kinds)

    def test_holdout_is_separate_and_improved(self):
        metrics = evaluate_holdout()
        self.assertEqual(metrics["v0_projection"]["TP"], 4)
        self.assertEqual(metrics["v0_projection"]["FP"], 8)
        self.assertEqual(metrics["v0_projection"]["FN"], 4)
        self.assertEqual(metrics["v1"]["TP"], 8)
        self.assertEqual(metrics["v1"]["FP"], 0)
        self.assertEqual(metrics["v1"]["FN"], 0)
        self.assertFalse(metrics["labels_available_to_detector"])

    def test_legitimate_admin_activity_not_flagged(self):
        benign = [rows for name, rows, labels in corpus() if name.startswith("benign") and not labels]
        self.assertTrue(benign); self.assertTrue(all(not find(rows) for rows in benign))

    def test_independent_recompute_exact(self):
        self.assertEqual(self.report, recompute(self.events))
        self.assertTrue(verify_report(self.events, self.report).startswith("RECOMPUTE_MATCH"))

    def test_report_tamper_refuted(self):
        changed = copy.deepcopy(self.report); changed["enforcement"] = "VERIFIED"
        with self.assertRaises(ReplayMismatch): verify_report(self.events, changed)

    def test_reference_policy_grid(self):
        template = event(1, 1)
        for op, role, verified, payload in itertools.product(
            ["READ_AGENT", "REGISTER_AGENT", "ADMIN_WRITE", "REGISTER_MCP", "RUN_TOOL", "MCP_CALL", "TELEGRAM_CALL"],
            ["OWNER", "ADMIN", "SERVICE", "ANON"], [False, True], ["SAFE", "UNSAFE_COMMAND"]
        ):
            row = dict(template, operation=op, token_role=role, token_verified=verified, payload=payload)
            self.assertEqual(evaluate(row), reference_decision(row))

    def test_reference_detector_randomized(self):
        for seed in range(20):
            rng = random.Random(seed); rows = []
            for seq in range(1, 40):
                row = event(seq, seq * 4)
                if rng.randrange(3) == 0: row["token_subject"] = "owner-b"
                if rng.randrange(4) == 0: row["token_wallet"] = "wallet-b"
                if rng.randrange(5) == 0: row["claimed_owner"] = "owner-b"
                rows.append(row)
            self.assertEqual(find(rows), reference_find(rows))
            self.assertEqual(produce_report(rows), recompute(rows))

    def test_strict_schema_and_json(self):
        changed = copy.deepcopy(self.events); changed[0]["extra"] = True
        with self.assertRaises(ReplayInputError): validate_events(changed)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"; path.write_bytes(b'{"schema":1,"schema":2}\n')
            with self.assertRaises(ReplayInputError): read_events(path)

    def test_mutations_have_working_controls(self):
        result = audit()
        self.assertEqual(result["population"], 15)
        self.assertEqual(result["counts"], {"KILLED": 15, "SURVIVED": 0, "NOT_APPLIED": 0, "CRASHED": 0, "CONTROL_BROKEN": 0})
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(all(row["applied"] and row["restored"] for row in result["results"]))

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); events = root / "events.jsonl"; report = root / "report.json"
            self.assertEqual(main(["fixture", "--out", str(events)]), 0)
            self.assertEqual(main(["run", "--events", str(events), "--out", str(report)]), 0)
            self.assertEqual(main(["verify", "--events", str(events), "--report", str(report)]), 0)
            self.assertEqual(main(["evaluate", "--out", str(root / "metrics.json")]), 0)
            self.assertEqual(main(["mutations", "--out", str(root / "mutations.json")]), 0)

    def test_external_effect_is_not_allow(self):
        row = event(1, 1, subject="attacker", wallet="wallet-attacker", role="ANON", verified=False,
                    operation="EXTERNAL_EFFECT", agent="none", claimed_owner="none", proof=False,
                    service="UNKNOWN", destination="UNKNOWN", payload="UNKNOWN")
        self.assertEqual(evaluate(row)["verdict"], "NOT_COVERED")


if __name__ == "__main__":
    unittest.main()

