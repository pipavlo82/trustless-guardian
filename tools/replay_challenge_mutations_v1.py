"""Physical replay/challenge/receipt source mutations with restored controls."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SPECS = (
    ("challenge-session-binding", "research/replay_challenge_v1/durable.py", 'if row["session_id"] != session_id:', 'if False and row["session_id"] != session_id:', "test_cross_session_challenge"),
    ("challenge-atomic-consume", "research/replay_challenge_v1/durable.py", "AND binding_sha256=? AND state='ISSUED' AND expires_at>?", "AND binding_sha256=? AND state IN ('ISSUED','CONSUMED') AND expires_at>?", "test_atomic_consume_rejects_preinspected_race"),
    ("challenge-message-binding", "research/replay_challenge_v1/challenge.py", "    if (\n        parsed.domain != record[\"domain\"]", "    if False and (\n        parsed.domain != record[\"domain\"]", "test_altered_nonce"),
    ("challenge-resource-binding", "research/replay_challenge_v1/challenge.py", "if resources != challenged_resources(binding, challenge_id, session_id):", "if False and resources != challenged_resources(binding, challenge_id, session_id):", "test_altered_resources"),
    ("challenge-consumption", "research/replay_challenge_v1/challenge.py", "    durable_state.consume_challenge(record, now)", "    if False:\n        durable_state.consume_challenge(record, now)", "test_duplicate_challenge"),
    ("durable-state-fail-closed", "research/replay_challenge_v1/durable.py", "if self._closed:", "if False and self._closed:", "test_admission_state_unavailable_fails_closed"),
    ("execution-admission-identity", "research/replay_challenge_v1/execution.py", '        claim = durable_state.prepare_admission(\n            payload["grant_id"],', '        claim = durable_state.prepare_admission(\n            "mutant-" + secrets.token_hex(16),', "test_execution_records_executed_and_refuses_replay"),
    ("grant-scope-binding", "research/replay_challenge_v1/scoped_grant.py", 'if payload["admission_scope"] != expected_scope:', 'if False and payload["admission_scope"] != expected_scope:', "test_scoped_grant_rejects_scope_substitution"),
    ("grant-worker-binding", "research/replay_challenge_v1/scoped_grant.py", 'if payload["worker_sha256"] != expected_worker_sha256:', 'if False and payload["worker_sha256"] != expected_worker_sha256:', "test_scoped_grant_rejects_worker_substitution"),
    ("grant-image-binding", "research/replay_challenge_v1/scoped_grant.py", 'if payload["image_identity"] != expected_image_identity:', 'if False and payload["image_identity"] != expected_image_identity:', "test_scoped_grant_rejects_image_substitution"),
    ("grant-trust-binding", "research/replay_challenge_v1/scoped_grant.py", 'if payload["trust_version"] != expected_trust_version:', 'if False and payload["trust_version"] != expected_trust_version:', "test_scoped_grant_rejects_trust_version_substitution"),
    ("grant-key-binding", "research/replay_challenge_v1/scoped_grant.py", '    if (\n        grant["public_key_fingerprint"] != expected_key_fingerprint', '    if False and (\n        grant["public_key_fingerprint"] != expected_key_fingerprint', "test_scoped_grant_rejects_key_fingerprint_substitution"),
    ("committed-state-persistence", "research/replay_challenge_v1/execution.py", "                durable_state.mark_committed(claim, now, outcome_sha256, exit_code)", "                claim.update(state=\"COMMITTED\")", "test_execution_records_executed_and_refuses_replay"),
    ("ambiguous-no-retry", "research/replay_challenge_v1/execution.py", '            if timed_out:\n                execution_state = "RECOVERY_REQUIRED"\n                lifecycle = "RECOVERY_REQUIRED"\n                durable_state.mark_recovery_required(claim, now, outcome_sha256)', '            if timed_out:\n                execution_state = "ABORTED"\n                lifecycle = "ABORTED"\n                durable_state.mark_aborted(claim, now, outcome_sha256)', "test_timeout_records_recovery_required"),
    ("container-start-observation", "research/replay_challenge_v1/execution.py", "        container_started = container_id is not None", "        container_started = process is not None", "test_docker_cli_failure_without_container_identity_never_claims_execution"),
    ("receipt-signature", "research/replay_challenge_v1/receipt.py", "            receipt_public_key.verify(signature, canonical_json_bytes(payload))", "            signature = bytes(signature)", "test_independent_receipt_verifier_refutes_signature_mutation"),
    ("receipt-type-discipline", "research/replay_challenge_v1/receipt.py", '            or type(payload["container_started"]) is not bool', "            or False", "test_independent_receipt_verifier_refutes_signed_type_confusion"),
    ("receipt-lifecycle-contradiction", "research/replay_challenge_v1/receipt.py", '        if payload["lifecycle"] == "COMMITTED" and (', '        if False and payload["lifecycle"] == "COMMITTED" and (', "test_independent_receipt_verifier_refutes_signed_lifecycle_contradiction"),
    ("receipt-evidence-hash", "research/replay_challenge_v1/receipt.py", '        if payload["evidence_sha256"] != _sha(canonical_json_bytes(observed)):', '        if False and payload["evidence_sha256"] != _sha(canonical_json_bytes(observed)):', "test_independent_receipt_verifier_refutes_evidence_hash_mutation"),
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def invoke(root, test_name, timeout):
    command = [
        sys.executable,
        "-B",
        "-m",
        "unittest",
        "-q",
        "tests_replay_v1.test_replay_challenge_v1.ReplayChallengeTests." + test_name,
    ]
    try:
        process = subprocess.run(command, cwd=root, capture_output=True, timeout=timeout)
        return {
            "exit_code": process.returncode,
            "timed_out": False,
            "stdout_sha256": sha(process.stdout),
            "stderr_sha256": sha(process.stderr),
        }
    except subprocess.TimeoutExpired as error:
        return {
            "exit_code": None,
            "timed_out": True,
            "stdout_sha256": sha(error.stdout or b""),
            "stderr_sha256": sha(error.stderr or b""),
        }


def run(out, timeout):
    results = []
    with tempfile.TemporaryDirectory(prefix="guardian-replay-mutations-") as temp:
        root = Path(temp)
        (root / "research").mkdir()
        (root / "research/__init__.py").write_bytes(b"")
        for folder in ("auth_gateway_v1", "replay_challenge_v1", "linux_isolated_worker_v2"):
            shutil.copytree(ROOT / "research" / folder, root / "research" / folder)
        shutil.copytree(ROOT / "tests_auth_v1", root / "tests_auth_v1")
        shutil.copytree(ROOT / "tests_replay_v1", root / "tests_replay_v1")
        for name, relative, old, new, test_name in SPECS:
            path = root / relative
            original = path.read_bytes()
            text = original.decode("utf-8")
            baseline = invoke(root, test_name, timeout)
            matches = text.count(old)
            applied = matches == 1
            mutant = text.replace(old, new, 1).encode("utf-8") if applied else original
            path.write_bytes(mutant)
            mutated = invoke(root, test_name, timeout) if applied else None
            path.write_bytes(original)
            restored_bytes = path.read_bytes() == original
            restored = invoke(root, test_name, timeout)
            if baseline["exit_code"] != 0 or restored["exit_code"] != 0 or not restored_bytes:
                status = "CONTROL_BROKEN"
            elif not applied:
                status = "NOT_APPLIED"
            elif mutated["timed_out"] or mutated["exit_code"] not in (0, 1):
                status = "CRASHED"
            elif mutated["exit_code"] == 0:
                status = "SURVIVED"
            else:
                status = "KILLED"
            results.append(
                {
                    "mutation": name,
                    "path": relative,
                    "test": test_name,
                    "match_count": matches,
                    "applied": applied,
                    "status": status,
                    "restored": restored_bytes,
                    "original_sha256": sha(original),
                    "mutant_sha256": sha(mutant),
                    "baseline": baseline,
                    "mutated": mutated,
                    "restored_control": restored,
                }
            )
    statuses = ("KILLED", "SURVIVED", "NOT_APPLIED", "CRASHED", "CONTROL_BROKEN")
    counts = {status: sum(row["status"] == status for row in results) for status in statuses}
    passed = counts == {
        "KILLED": len(results),
        "SURVIVED": 0,
        "NOT_APPLIED": 0,
        "CRASHED": 0,
        "CONTROL_BROKEN": 0,
    }
    report = {
        "schema": "guardian.replay-challenge-source-mutations.v1",
        "population": len(results),
        "counts": counts,
        "results": results,
        "verdict": "PASS" if passed else "HOLD",
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii", newline="\n")
    print(json.dumps({"counts": counts, "verdict": report["verdict"]}, sort_keys=True))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args(argv)
    return 0 if run(args.out, args.timeout)["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
