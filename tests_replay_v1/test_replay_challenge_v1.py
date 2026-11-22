import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_account import Account

from research.auth_gateway_v1.errors import SecurityError
from research.auth_gateway_v1.canonical import canonical_json_bytes
from research.auth_gateway_v1.model import RequestBinding
from research.replay_challenge_v1.challenge import authenticate_challenged_siwe
from research.replay_challenge_v1.durable import DurableSecurityState
from research.replay_challenge_v1.execution import execute_confined
from research.replay_challenge_v1.gateway import GuardianChallengeGateway
from research.replay_challenge_v1.receipt import verify_execution_evidence
from research.replay_challenge_v1.scoped_grant import verify_scoped_execution_grant
from tests_auth_v1.fixtures import Fixture
from tests_replay_v1.fixtures import make_message, rfc3339


ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "research/linux_isolated_worker_v2/worker.sh"
SCOPE = "guardian.test.worker.v1"
WORKER_SHA256 = hashlib.sha256(WORKER.read_bytes()).hexdigest()
IMAGE_IDENTITY = "sha256:" + ("1" * 64)


class ReplayChallengeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="guardian-replay-tests-")
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "state.sqlite3"
        self.fixture = Fixture()
        self.receipt_key = Ed25519PrivateKey.generate()
        self.state = DurableSecurityState(self.db, SCOPE, admission_capacity=64, challenge_capacity=64)
        self.session = "session-" + secrets.token_hex(8)
        self.gateway = self.make_gateway(self.state)

    def make_gateway(self, state):
        return GuardianChallengeGateway(
            self.fixture.trust,
            self.fixture.jwt_nonces,
            state,
            self.fixture.grant_key,
            SCOPE,
            WORKER_SHA256,
            IMAGE_IDENTITY,
        )

    def challenge(self, session=None):
        return self.gateway.issue_challenge(
            self.fixture.request,
            self.fixture.owner.address,
            self.session if session is None else session,
            self.fixture.now,
        )

    def authorize(self, challenge, message=None, signature=None, session=None, challenge_id=None, now=None):
        if message is None:
            message, signature = make_message(challenge, self.fixture.binding, self.fixture.owner)
        return self.gateway.authorize_and_issue(
            self.fixture.make_jwt(),
            challenge["challenge_id"] if challenge_id is None else challenge_id,
            self.session if session is None else session,
            message,
            signature,
            self.fixture.mcp_header(),
            self.fixture.request,
            self.fixture.now if now is None else now,
            "grant-" + secrets.token_hex(8),
        )

    def denied(self, code, challenge, **kwargs):
        with self.assertRaises(SecurityError) as caught:
            self.authorize(challenge, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def issue_grant(self):
        challenge = self.challenge()
        return self.authorize(challenge)["grant"]

    def verified(
        self,
        grant,
        binding=None,
        scope=SCOPE,
        worker_sha256=WORKER_SHA256,
        image_identity=IMAGE_IDENTITY,
        trust_version=None,
    ):
        return verify_scoped_execution_grant(
            grant,
            self.fixture.grant_key.public_key(),
            self.fixture.now,
            scope,
            self.fixture.binding if binding is None else binding,
            worker_sha256,
            image_identity,
            self.fixture.trust.version if trust_version is None else trust_version,
        )

    def verify_receipt(self, grant, receipt, request=None):
        return verify_execution_evidence(
            self.fixture.request if request is None else request,
            grant,
            receipt,
            self.fixture.grant_key.public_key(),
            self.receipt_key.public_key(),
            SCOPE,
            WORKER_SHA256,
            IMAGE_IDENTITY,
            self.fixture.trust.version,
        )

    def claim(self, grant, session=None, attempt=None):
        payload, digest = self.verified(grant)
        return self.state.prepare_admission(
            payload["grant_id"],
            digest,
            payload["binding_sha256"],
            self.session if session is None else session,
            "attempt-" + secrets.token_hex(8) if attempt is None else attempt,
            self.fixture.now,
            payload["expires_at"],
        )

    def test_positive_challenge_auth_and_scoped_grant(self):
        challenge = self.challenge()
        result = self.authorize(challenge)
        self.assertEqual(
            result["sequence"],
            ["SERVER_CHALLENGE", "AUTHENTICATE", "AUTHORIZE", "DURABLE_ADMISSION_PENDING"],
        )
        payload, digest = self.verified(result["grant"])
        self.assertEqual(payload["admission_scope"], SCOPE)
        self.assertEqual(len(digest), 64)

    def test_unsolicited_challenge_rejected_without_consuming_valid_one(self):
        challenge = self.challenge()
        message, signature = make_message(challenge, self.fixture.binding, self.fixture.owner)
        self.denied(
            "SIWE_CHALLENGE_UNSOLICITED",
            challenge,
            message=message,
            signature=signature,
            challenge_id="missing-" + secrets.token_hex(8),
        )
        self.assertEqual(self.authorize(challenge, message=message, signature=signature)["authorization"]["verdict"], "ALLOW")

    def test_expired_challenge(self):
        challenge = self.challenge()
        self.denied("SIWE_CHALLENGE_EXPIRED", challenge, now=challenge["expires_at"])

    def test_duplicate_challenge(self):
        challenge = self.challenge()
        message, signature = make_message(challenge, self.fixture.binding, self.fixture.owner)
        self.authorize(challenge, message=message, signature=signature)
        self.denied("SIWE_CHALLENGE_DUPLICATE", challenge, message=message, signature=signature)

    def test_cross_session_challenge(self):
        challenge = self.challenge()
        message, signature = make_message(challenge, self.fixture.binding, self.fixture.owner)
        self.denied(
            "SIWE_CHALLENGE_CROSS_SESSION",
            challenge,
            message=message,
            signature=signature,
            session="other-session",
        )
        self.authorize(challenge, message=message, signature=signature)

    def test_cross_challenge_substitution(self):
        first = self.challenge()
        second = self.challenge()
        message, signature = make_message(first, self.fixture.binding, self.fixture.owner)
        self.denied(
            "SIWE_CHALLENGE_MESSAGE_BINDING",
            second,
            message=message,
            signature=signature,
        )

    def altered_message_denied(self, **overrides):
        challenge = self.challenge()
        message, signature = make_message(challenge, self.fixture.binding, self.fixture.owner, **overrides)
        self.denied(
            "SIWE_CHALLENGE_MESSAGE_BINDING",
            challenge,
            message=message,
            signature=signature,
        )
        self.authorize(challenge)

    def test_altered_domain(self):
        self.altered_message_denied(domain="wrong.local")

    def test_altered_uri(self):
        self.altered_message_denied(uri="https://guardian.local/other")

    def test_altered_chain(self):
        self.altered_message_denied(chain_id=1)

    def test_altered_nonce(self):
        self.altered_message_denied(nonce=secrets.token_hex(16))

    def test_altered_request_id(self):
        self.altered_message_denied(request_id="req-other")

    def test_altered_wallet(self):
        challenge = self.challenge()
        other = Account.create()
        message, signature = make_message(
            challenge,
            self.fixture.binding,
            other,
            address=other.address,
        )
        self.denied(
            "SIWE_CHALLENGE_MESSAGE_BINDING",
            challenge,
            message=message,
            signature=signature,
        )
        self.authorize(challenge)

    def test_altered_expiry(self):
        challenge = self.challenge()
        message, signature = make_message(
            challenge,
            self.fixture.binding,
            self.fixture.owner,
            expiration_time=rfc3339(challenge["expires_at"] + 1),
        )
        self.denied(
            "SIWE_CHALLENGE_TIME_BINDING",
            challenge,
            message=message,
            signature=signature,
        )
        self.authorize(challenge)

    def test_altered_resources(self):
        challenge = self.challenge()
        message, signature = make_message(
            challenge,
            self.fixture.binding,
            self.fixture.owner,
            resources=["urn:guardian:challenge:attacker"],
        )
        self.denied(
            "SIWE_CHALLENGE_RESOURCE_BINDING",
            challenge,
            message=message,
            signature=signature,
        )
        self.authorize(challenge)

    def test_request_body_binding(self):
        challenge = self.challenge()
        message, signature = make_message(challenge, self.fixture.binding, self.fixture.owner)
        mutated = copy.deepcopy(self.fixture.request)
        mutated["body"]["value"] = 999
        with self.assertRaises(SecurityError) as caught:
            authenticate_challenged_siwe(
                message,
                signature,
                challenge["challenge_id"],
                self.session,
                RequestBinding.from_request(mutated),
                self.fixture.owner.address,
                self.fixture.trust,
                self.state,
                self.fixture.now,
            )
        self.assertEqual(caught.exception.code, "SIWE_CHALLENGE_BINDING")

    def test_forged_signature_does_not_consume_challenge(self):
        challenge = self.challenge()
        message, _ = make_message(challenge, self.fixture.binding, self.fixture.owner)
        _, wrong_signature = make_message(challenge, self.fixture.binding, Account.create())
        self.denied(
            "SIWE_CRYPTO_OR_TIME",
            challenge,
            message=message,
            signature=wrong_signature,
        )
        self.authorize(challenge)

    def test_concurrent_challenge_exactly_one_consumed(self):
        challenge = self.challenge()
        message, signature = make_message(challenge, self.fixture.binding, self.fixture.owner)
        tokens = [self.fixture.make_jwt() for _ in range(8)]
        barrier = threading.Barrier(8)

        def worker(index):
            barrier.wait()
            try:
                self.gateway.authorize_and_issue(
                    tokens[index],
                    challenge["challenge_id"],
                    self.session,
                    message,
                    signature,
                    self.fixture.mcp_header(),
                    self.fixture.request,
                    self.fixture.now,
                    "grant-concurrent-" + str(index),
                )
                return "ALLOW"
            except SecurityError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        self.assertEqual(results.count("ALLOW"), 1)
        self.assertEqual(results.count("SIWE_CHALLENGE_DUPLICATE"), 7)

    def test_atomic_consume_rejects_preinspected_race(self):
        challenge = self.challenge()
        record = self.state.inspect_challenge(
            challenge["challenge_id"],
            self.session,
            challenge["domain"],
            challenge["uri"],
            challenge["wallet"],
            challenge["chain_id"],
            challenge["request_id"],
            challenge["binding_sha256"],
            self.fixture.now,
        )
        barrier = threading.Barrier(8)

        def worker(_index):
            barrier.wait()
            try:
                self.state.consume_challenge(record, self.fixture.now)
                return "CONSUMED"
            except SecurityError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        self.assertEqual(results.count("CONSUMED"), 1)
        self.assertEqual(results.count("SIWE_CHALLENGE_DUPLICATE"), 7)

    def test_challenge_survives_state_restart(self):
        challenge = self.challenge()
        message, signature = make_message(challenge, self.fixture.binding, self.fixture.owner)
        restarted = DurableSecurityState(self.db, SCOPE)
        gateway = self.make_gateway(restarted)
        result = gateway.authorize_and_issue(
            self.fixture.make_jwt(),
            challenge["challenge_id"],
            self.session,
            message,
            signature,
            self.fixture.mcp_header(),
            self.fixture.request,
            self.fixture.now,
            "grant-restart-challenge",
        )
        self.assertEqual(result["authorization"]["verdict"], "ALLOW")

    def test_challenge_state_unavailable_fails_closed(self):
        challenge = self.challenge()
        self.state.close()
        self.denied("DURABLE_STATE_UNAVAILABLE", challenge)

    def test_challenge_capacity_fails_closed(self):
        other_db = Path(self.temp.name) / "capacity.sqlite3"
        state = DurableSecurityState(other_db, SCOPE, challenge_capacity=1)
        gateway = self.make_gateway(state)
        gateway.issue_challenge(self.fixture.request, self.fixture.owner.address, self.session, self.fixture.now)
        with self.assertRaises(SecurityError) as caught:
            gateway.issue_challenge(self.fixture.request, self.fixture.owner.address, self.session, self.fixture.now)
        self.assertEqual(caught.exception.code, "DURABLE_CHALLENGE_FULL")

    def test_inconsistent_durable_schema_fails_closed(self):
        self.state.close()
        connection = sqlite3.connect(self.db)
        connection.execute("UPDATE metadata SET value='tampered' WHERE name='schema'")
        connection.commit()
        connection.close()
        with self.assertRaises(SecurityError) as caught:
            DurableSecurityState(self.db, SCOPE)
        self.assertEqual(caught.exception.code, "DURABLE_STATE_INCONSISTENT")

    def test_scoped_grant_rejects_scope_substitution(self):
        grant = self.issue_grant()
        with self.assertRaises(SecurityError) as caught:
            self.verified(grant, scope="guardian.other.worker")
        self.assertEqual(caught.exception.code, "GRANT_SCOPE")

    def test_scoped_grant_rejects_worker_substitution(self):
        grant = self.issue_grant()
        with self.assertRaises(SecurityError) as caught:
            self.verified(grant, worker_sha256="0" * 64)
        self.assertEqual(caught.exception.code, "GRANT_WORKER_BINDING")

    def test_scoped_grant_rejects_image_substitution(self):
        grant = self.issue_grant()
        with self.assertRaises(SecurityError) as caught:
            self.verified(grant, image_identity="sha256:" + ("2" * 64))
        self.assertEqual(caught.exception.code, "GRANT_IMAGE_BINDING")

    def test_scoped_grant_rejects_trust_version_substitution(self):
        grant = self.issue_grant()
        with self.assertRaises(SecurityError) as caught:
            self.verified(grant, trust_version="stale-trust")
        self.assertEqual(caught.exception.code, "GRANT_TRUST_BINDING")

    def test_scoped_grant_rejects_key_fingerprint_substitution(self):
        grant = self.issue_grant()
        grant["public_key_fingerprint"] = "0" * 64
        with self.assertRaises(SecurityError) as caught:
            self.verified(grant)
        self.assertEqual(caught.exception.code, "GRANT_KEY_BINDING")

    def test_scoped_grant_rejects_payload_mutation(self):
        grant = self.issue_grant()
        grant["payload"]["admission_scope"] = "guardian.other.worker"
        with self.assertRaises(SecurityError) as caught:
            self.verified(grant)
        self.assertEqual(caught.exception.code, "GRANT_SIGNATURE")

    def test_scoped_grant_rejects_request_mutation(self):
        grant = self.issue_grant()
        mutated = copy.deepcopy(self.fixture.request)
        mutated["body"]["value"] = 8
        with self.assertRaises(SecurityError) as caught:
            self.verified(grant, RequestBinding.from_request(mutated))
        self.assertEqual(caught.exception.code, "GRANT_REQUEST_BINDING")

    def test_sequential_admission_replay_states(self):
        grant = self.issue_grant()
        claim = self.claim(grant)
        with self.assertRaises(SecurityError) as caught:
            self.claim(grant)
        self.assertEqual(caught.exception.code, "GRANT_REPLAY_PREPARED")
        self.state.mark_committed(claim, self.fixture.now, "a" * 64, 0)
        with self.assertRaises(SecurityError) as caught:
            self.claim(grant)
        self.assertEqual(caught.exception.code, "GRANT_REPLAY_COMMITTED")

    def test_concurrent_thread_admission_exactly_one(self):
        grant = self.issue_grant()
        barrier = threading.Barrier(8)

        def worker(index):
            barrier.wait()
            try:
                self.claim(grant, attempt="attempt-thread-" + str(index))
                return "PREPARED"
            except SecurityError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        self.assertEqual(results.count("PREPARED"), 1)
        self.assertEqual(results.count("GRANT_REPLAY_PREPARED"), 7)

    def process_state_file(self, grant):
        public = self.fixture.grant_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        path = Path(self.temp.name) / "process-state.json"
        path.write_text(
            json.dumps(
                {
                    "grant": grant,
                    "now": self.fixture.now,
                    "public_key": base64.b64encode(public).decode("ascii"),
                    "request": self.fixture.request,
                    "worker_sha256": WORKER_SHA256,
                    "image_identity": IMAGE_IDENTITY,
                    "trust_version": self.fixture.trust.version,
                },
                sort_keys=True,
            ),
            encoding="ascii",
            newline="\n",
        )
        return path

    def process_command(self, state_path, session, mode="execute", delay=0.0):
        return [
            sys.executable,
            "-B",
            "-m",
            "tests_replay_v1.process_worker",
            "--db",
            str(self.db),
            "--state",
            str(state_path),
            "--scope",
            SCOPE,
            "--session",
            session,
            "--mode",
            mode,
            "--delay",
            str(delay),
        ]

    def test_process_restart_rejects_executed_grant(self):
        grant = self.issue_grant()
        state_path = self.process_state_file(grant)
        first = subprocess.run(self.process_command(state_path, "process-one"), cwd=ROOT, capture_output=True, text=True, timeout=30)
        second = subprocess.run(self.process_command(state_path, "process-two"), cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(json.loads(first.stdout)["status"], "EXECUTED")
        self.assertEqual(json.loads(second.stdout), {"reason": "GRANT_REPLAY_COMMITTED", "status": "REFUSED"})

    def test_concurrent_process_admission_exactly_one(self):
        grant = self.issue_grant()
        state_path = self.process_state_file(grant)
        processes = [
            subprocess.Popen(
                self.process_command(state_path, "process-" + str(index), delay=0.3),
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for index in range(6)
        ]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stderr)
            results.append(json.loads(stdout))
        self.assertEqual(sum(row["status"] == "EXECUTED" for row in results), 1)
        self.assertEqual(sum(row["status"] == "REFUSED" for row in results), 5)

    def test_process_restart_incomplete_requires_explicit_recovery(self):
        grant = self.issue_grant()
        state_path = self.process_state_file(grant)
        first = subprocess.run(
            self.process_command(state_path, "terminated-process", mode="claim-only"),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        second = subprocess.run(
            self.process_command(state_path, "replacement-process"),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(json.loads(first.stdout)["status"], "PREPARED")
        self.assertEqual(json.loads(second.stdout)["reason"], "GRANT_REPLAY_PREPARED")
        payload, digest = self.verified(grant)
        self.state.require_recovery(payload["grant_id"], digest, payload["binding_sha256"], self.fixture.now)
        self.assertEqual(self.state.read_admission(payload["grant_id"])["state"], "RECOVERY_REQUIRED")

    def test_ambiguous_outcome_requires_recovery_and_blocks_replay(self):
        grant = self.issue_grant()
        claim = self.claim(grant)
        self.state.mark_recovery_required(claim, self.fixture.now, "b" * 64)
        with self.assertRaises(SecurityError) as caught:
            self.claim(grant)
        self.assertEqual(caught.exception.code, "GRANT_RECOVERY_REQUIRED")

    def test_recovery_required_blocks_replay(self):
        grant = self.issue_grant()
        claim = self.claim(grant)
        self.state.mark_recovery_required(claim, self.fixture.now, "c" * 64)
        with self.assertRaises(SecurityError) as caught:
            self.claim(grant)
        self.assertEqual(caught.exception.code, "GRANT_RECOVERY_REQUIRED")

    def test_admission_state_unavailable_fails_closed(self):
        grant = self.issue_grant()
        self.state.close()
        with self.assertRaises(SecurityError) as caught:
            self.claim(grant)
        self.assertEqual(caught.exception.code, "DURABLE_STATE_UNAVAILABLE")

    def test_admission_capacity_fails_closed(self):
        db = Path(self.temp.name) / "admission-capacity.sqlite3"
        state = DurableSecurityState(db, SCOPE, admission_capacity=1)
        first = self.issue_grant()
        second = self.issue_grant()
        for grant, attempt in ((first, "first"),):
            payload, digest = self.verified(grant)
            state.prepare_admission(payload["grant_id"], digest, payload["binding_sha256"], self.session, attempt, self.fixture.now, payload["expires_at"])
        payload, digest = self.verified(second)
        with self.assertRaises(SecurityError) as caught:
            state.prepare_admission(payload["grant_id"], digest, payload["binding_sha256"], self.session, "second", self.fixture.now, payload["expires_at"])
        self.assertEqual(caught.exception.code, "DURABLE_ADMISSION_FULL")

    def execute_with_runner(self, runner):
        grant = self.issue_grant()
        result = execute_confined(
            image=IMAGE_IDENTITY,
            request=self.fixture.request,
            public_key=self.fixture.grant_key.public_key(),
            grant=grant,
            receipt_private_key=self.receipt_key,
            secret_value="fixture-secret",
            label="unit",
            durable_state=self.state,
            admission_scope=SCOPE,
            trust_version=self.fixture.trust.version,
            session_id=self.session,
            now=self.fixture.now,
            worker_path=WORKER,
            runner=runner,
            root=ROOT,
        )
        return grant, result

    @staticmethod
    def observed_container_result(argv, returncode=0, stdout=b"{}", stderr=b""):
        cidfile = Path(argv[argv.index("--cidfile") + 1])
        cidfile.write_text(("a" * 64) + "\n", encoding="ascii", newline="\n")
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)

    def test_execution_records_executed_and_refuses_replay(self):
        calls = []

        def runner(argv, timeout, cwd):
            calls.append(argv)
            return self.observed_container_result(argv)

        grant, result = self.execute_with_runner(runner)
        self.assertEqual(result["execution_state"], "EXECUTED")
        replay = execute_confined(
            IMAGE_IDENTITY, self.fixture.request, self.fixture.grant_key.public_key(), grant, self.receipt_key,
            "fixture-secret", "replay", self.state, SCOPE, self.fixture.trust.version, self.session, self.fixture.now,
            WORKER, runner, ROOT,
        )
        self.assertFalse(replay["container_started"])
        self.assertEqual(replay["reason"], "GRANT_REPLAY_COMMITTED")
        self.assertEqual(len(calls), 1)

    def test_independent_receipt_verifier_classifies_executed(self):
        def runner(argv, timeout, cwd):
            return self.observed_container_result(argv)

        grant, result = self.execute_with_runner(runner)
        recomputed = self.verify_receipt(grant, result["receipt"])
        self.assertTrue(recomputed["verified"])
        self.assertEqual(recomputed["classification"], "EXECUTED")

    def test_independent_receipt_verifier_refutes_mutation(self):
        def runner(argv, timeout, cwd):
            return self.observed_container_result(argv)

        grant, result = self.execute_with_runner(runner)
        result["receipt"]["payload"]["exit_code"] = 9
        recomputed = self.verify_receipt(grant, result["receipt"])
        self.assertEqual(recomputed["classification"], "REFUTED")
        self.assertFalse(recomputed["verified"])

    def test_independent_receipt_verifier_refutes_signature_mutation(self):
        def runner(argv, timeout, cwd):
            return self.observed_container_result(argv)

        grant, result = self.execute_with_runner(runner)
        result["receipt"]["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
        recomputed = self.verify_receipt(grant, result["receipt"])
        self.assertEqual(recomputed, {"classification": "REFUTED", "verified": False, "reason": "RECEIPT_SIGNATURE"})

    def test_independent_receipt_verifier_refutes_signed_type_confusion(self):
        def runner(argv, timeout, cwd):
            return self.observed_container_result(argv)

        grant, result = self.execute_with_runner(runner)
        receipt = result["receipt"]
        receipt["payload"]["container_started"] = 1
        receipt["signature"] = base64.b64encode(
            self.receipt_key.sign(canonical_json_bytes(receipt["payload"]))
        ).decode("ascii")
        recomputed = self.verify_receipt(grant, receipt)
        self.assertEqual(recomputed, {"classification": "REFUTED", "verified": False, "reason": "RECEIPT_FIELD_TYPE"})

    def test_independent_receipt_verifier_refutes_signed_lifecycle_contradiction(self):
        def runner(argv, timeout, cwd):
            return self.observed_container_result(argv)

        grant, result = self.execute_with_runner(runner)
        receipt = result["receipt"]
        receipt["payload"]["timed_out"] = True
        observed = {
            name: receipt["payload"][name]
            for name in (
                "container_started",
                "exit_code",
                "timed_out",
                "launch_error",
                "outcome_sha256",
                "stdout_sha256",
                "stderr_sha256",
            )
        }
        receipt["payload"]["evidence_sha256"] = hashlib.sha256(canonical_json_bytes(observed)).hexdigest()
        receipt["signature"] = base64.b64encode(
            self.receipt_key.sign(canonical_json_bytes(receipt["payload"]))
        ).decode("ascii")
        recomputed = self.verify_receipt(grant, receipt)
        self.assertEqual(
            recomputed,
            {"classification": "REFUTED", "verified": False, "reason": "RECEIPT_EXECUTION_CONTRADICTION"},
        )

    def test_independent_receipt_verifier_refutes_evidence_hash_mutation(self):
        def runner(argv, timeout, cwd):
            return self.observed_container_result(argv)

        grant, result = self.execute_with_runner(runner)
        receipt = result["receipt"]
        receipt["payload"]["evidence_sha256"] = "0" * 64
        receipt["signature"] = base64.b64encode(
            self.receipt_key.sign(canonical_json_bytes(receipt["payload"]))
        ).decode("ascii")
        recomputed = self.verify_receipt(grant, receipt)
        self.assertEqual(recomputed, {"classification": "REFUTED", "verified": False, "reason": "RECEIPT_EVIDENCE"})

    def test_independent_receipt_verifier_refutes_request_substitution(self):
        def runner(argv, timeout, cwd):
            return self.observed_container_result(argv)

        grant, result = self.execute_with_runner(runner)
        altered = copy.deepcopy(self.fixture.request)
        altered["body"]["value"] = 99
        recomputed = self.verify_receipt(grant, result["receipt"], altered)
        self.assertEqual(recomputed["classification"], "REFUTED")

    def test_independent_receipt_verifier_missing_is_unverifiable(self):
        grant = self.issue_grant()
        recomputed = self.verify_receipt(grant, None)
        self.assertEqual(recomputed["classification"], "UNVERIFIABLE")

    def test_timeout_records_recovery_required(self):
        def runner(argv, timeout, cwd):
            raise subprocess.TimeoutExpired(argv, timeout, output=b"partial", stderr=b"")

        grant, result = self.execute_with_runner(runner)
        self.assertEqual(result["execution_state"], "RECOVERY_REQUIRED")
        self.assertEqual(result["lifecycle"], "RECOVERY_REQUIRED")
        self.assertFalse(result["container_started"])
        self.assertEqual(result["start_observation_error"], "CONTAINER_START_NOT_OBSERVED")
        payload, _ = self.verified(grant)
        self.assertEqual(self.state.read_admission(payload["grant_id"])["state"], "RECOVERY_REQUIRED")

    def test_timeout_after_observed_start_records_recovery_required(self):
        def runner(argv, timeout, cwd):
            cidfile = Path(argv[argv.index("--cidfile") + 1])
            cidfile.write_text(("b" * 64) + "\n", encoding="ascii", newline="\n")
            raise subprocess.TimeoutExpired(argv, timeout, output=b"partial", stderr=b"")

        grant, result = self.execute_with_runner(runner)
        self.assertEqual(result["execution_state"], "RECOVERY_REQUIRED")
        self.assertEqual(result["lifecycle"], "RECOVERY_REQUIRED")
        self.assertTrue(result["container_started"])
        self.assertIsNotNone(result["container_id_sha256"])
        payload, _ = self.verified(grant)
        self.assertEqual(self.state.read_admission(payload["grant_id"])["state"], "RECOVERY_REQUIRED")

    def test_launch_error_records_aborted(self):
        def runner(argv, timeout, cwd):
            raise OSError("synthetic launch failure")

        grant, result = self.execute_with_runner(runner)
        self.assertEqual(result["execution_state"], "ABORTED")
        self.assertEqual(result["lifecycle"], "ABORTED")
        self.assertFalse(result["container_started"])
        self.assertEqual(self.verify_receipt(grant, result["receipt"])["classification"], "AUTHORIZED")

    def test_docker_cli_failure_without_container_identity_never_claims_execution(self):
        def runner(argv, timeout, cwd):
            return subprocess.CompletedProcess(argv, 125, stdout=b"", stderr=b"daemon unavailable")

        grant, result = self.execute_with_runner(runner)
        self.assertEqual(result["execution_state"], "RECOVERY_REQUIRED")
        self.assertEqual(result["lifecycle"], "RECOVERY_REQUIRED")
        self.assertFalse(result["container_started"])
        self.assertEqual(result["start_observation_error"], "CONTAINER_START_NOT_OBSERVED")
        self.assertEqual(self.verify_receipt(grant, result["receipt"])["classification"], "RECOVERY_REQUIRED")

    def test_recovery_receipt_does_not_claim_execution(self):
        def runner(argv, timeout, cwd):
            raise subprocess.TimeoutExpired(argv, timeout, output=b"partial", stderr=b"")

        grant, result = self.execute_with_runner(runner)
        recomputed = self.verify_receipt(grant, result["receipt"])
        self.assertTrue(recomputed["verified"])
        self.assertEqual(recomputed["classification"], "RECOVERY_REQUIRED")

    def test_outcome_persistence_failure_is_not_called_executed(self):
        def runner(argv, timeout, cwd):
            self.state.close()
            return self.observed_container_result(argv)

        grant, result = self.execute_with_runner(runner)
        self.assertEqual(result["execution_state"], "RECOVERY_REQUIRED")
        self.assertEqual(result["transition_error"], "DURABLE_STATE_UNAVAILABLE")
        restarted = DurableSecurityState(self.db, SCOPE)
        payload, digest = self.verified(grant)
        self.assertEqual(restarted.read_admission(payload["grant_id"])["state"], "PREPARED")
        restarted.require_recovery(payload["grant_id"], digest, payload["binding_sha256"], self.fixture.now)
        self.assertEqual(restarted.read_admission(payload["grant_id"])["state"], "RECOVERY_REQUIRED")


if __name__ == "__main__":
    unittest.main()
