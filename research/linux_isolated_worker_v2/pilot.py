"""Real local Docker/WSL containment with durable scoped grant admission."""

import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from research.auth_gateway_v1.errors import SecurityError
from research.auth_gateway_v1.model import RequestBinding
from research.replay_challenge_v1.challenge import prepare_challenge_message
from research.replay_challenge_v1.durable import DurableSecurityState
from research.replay_challenge_v1.execution import execute_confined
from research.replay_challenge_v1.gateway import GuardianChallengeGateway
from research.replay_challenge_v1.receipt import verify_execution_evidence
from research.replay_challenge_v1.scoped_grant import verify_scoped_execution_grant
from tests_auth_v1.fixtures import Fixture


ROOT = Path(__file__).resolve().parents[2]
WORKER = Path(__file__).with_name("worker.sh")
WORKER_SHA256 = hashlib.sha256(WORKER.read_bytes()).hexdigest()


def _run(argv, timeout=30, cwd=ROOT):
    return subprocess.run(argv, cwd=cwd, capture_output=True, timeout=timeout)


def _write_json(path, value):
    Path(path).write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
        newline="\n",
    )


def _issue(fixture, grant_id, durable_state, admission_scope, session_id, image_identity):
    gateway = GuardianChallengeGateway(
        fixture.trust,
        fixture.jwt_nonces,
        durable_state,
        fixture.grant_key,
        admission_scope,
        WORKER_SHA256,
        image_identity,
    )
    challenge = gateway.issue_challenge(
        fixture.request,
        fixture.owner.address,
        session_id,
        fixture.now,
    )
    message, signature = prepare_challenge_message(challenge, fixture.binding, fixture.owner)
    return gateway.authorize_and_issue(
        fixture.make_jwt(),
        challenge["challenge_id"],
        session_id,
        message,
        signature,
        fixture.mcp_header(),
        fixture.request,
        fixture.now,
        grant_id,
    )["grant"]


def _rootless_probe():
    if os.name == "nt" and shutil.which("wsl"):
        argv = [
            "wsl",
            "-d",
            "Ubuntu",
            "--",
            "unshare",
            "-Ur",
            "sh",
            "-c",
            "id -u; cat /proc/self/uid_map",
        ]
    elif os.name != "nt" and shutil.which("unshare"):
        argv = ["unshare", "-Ur", "sh", "-c", "id -u; cat /proc/self/uid_map"]
    else:
        return {"status": "NOT_COVERED", "reason": "UNSHARE_UNAVAILABLE"}
    try:
        process = _run(argv, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"status": "NOT_COVERED", "reason": type(error).__name__}
    output = process.stdout.decode("utf-8", errors="replace").strip()
    lines = output.splitlines()
    verified = process.returncode == 0 and lines[:1] == ["0"] and "1000" in output
    return {
        "status": "VERIFIED" if verified else "NOT_COVERED",
        "exit_code": process.returncode,
        "observation": output,
        "stderr": process.stderr.decode("utf-8", errors="replace")[:512],
    }


def _authorization_substitution(fixture, request, state, scope, session_id, image_identity):
    fixture.request = request
    fixture.binding = RequestBinding.from_request(request)
    gateway = GuardianChallengeGateway(
        fixture.trust,
        fixture.jwt_nonces,
        state,
        fixture.grant_key,
        scope,
        WORKER_SHA256,
        image_identity,
    )
    challenge = gateway.issue_challenge(request, fixture.owner.address, session_id, fixture.now)
    message, signature = prepare_challenge_message(challenge, fixture.binding, fixture.owner)
    try:
        gateway.authorize_and_issue(
            fixture.make_jwt(),
            challenge["challenge_id"],
            session_id,
            message,
            signature,
            fixture.mcp_header(),
            request,
            fixture.now,
            "grant-forbidden-" + secrets.token_hex(8),
        )
    except SecurityError as error:
        return {"verdict": "REFUSED", "reason": error.code, "grant_issued": False}
    return {"verdict": "UNEXPECTED_ALLOW", "grant_issued": True}


def _execute(image, fixture, grant, receipt_key, secret_value, label, durable_state, admission_scope, session_id):
    return execute_confined(
        image=image,
        request=fixture.request,
        public_key=fixture.grant_key.public_key(),
        grant=grant,
        receipt_private_key=receipt_key,
        secret_value=secret_value,
        label=label,
        durable_state=durable_state,
        admission_scope=admission_scope,
        trust_version=fixture.trust.version,
        session_id=session_id,
        now=fixture.now,
        worker_path=WORKER,
        runner=_run,
        root=ROOT,
    )


def run(out, image):
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": "guardian.linux-isolated-worker-result.v3",
        "scope": "LOCAL_DISPOSABLE_FIXTURES_ONLY",
        "production_ready": False,
        "third_party_targets": False,
        "image_pull": False,
        "rootless_user_namespace": _rootless_probe(),
    }
    if shutil.which("docker") is None:
        report.update(status="NOT_COVERED", reason="DOCKER_UNAVAILABLE")
        out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii", newline="\n")
        return report
    inspected = _run(["docker", "image", "inspect", image])
    if inspected.returncode:
        report.update(status="NOT_COVERED", reason="PINNED_LOCAL_IMAGE_UNAVAILABLE", image=image)
        out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii", newline="\n")
        return report
    image_data = json.loads(inspected.stdout)[0]
    requested_image = image
    image = image_data.get("Id")
    if type(image) is not str or not image.startswith("sha256:") or len(image) != 71:
        report.update(status="HOLD", reason="LOCAL_IMAGE_IDENTITY_INVALID", requested_image=requested_image)
        out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii", newline="\n")
        return report
    security = _run(["docker", "info", "--format", "{{json .SecurityOptions}}"])
    security_options = security.stdout.decode("utf-8", errors="replace").strip()
    report.update(
        requested_image=requested_image,
        image=image,
        image_id=image,
        repo_digests=image_data.get("RepoDigests", []),
        image_inspect_sha256=hashlib.sha256(inspected.stdout).hexdigest(),
        daemon_security_options=security_options,
        rootless_container_daemon="VERIFIED" if "rootless" in security_options.lower() else "NOT_COVERED",
    )
    try:
        sbom = _run(["docker", "sbom", "--format", "spdx-json", image], timeout=60)
        if sbom.returncode == 0 and sbom.stdout:
            report["sbom"] = {
                "status": "GENERATED_LOCAL_IMAGE",
                "sha256": hashlib.sha256(sbom.stdout).hexdigest(),
                "bytes": len(sbom.stdout),
            }
            (out.parent / "worker-image.spdx.json").write_bytes(sbom.stdout)
        else:
            report["sbom"] = {"status": "NOT_COVERED", "reason": "DOCKER_SBOM_UNAVAILABLE"}
    except (OSError, subprocess.TimeoutExpired):
        report["sbom"] = {"status": "NOT_COVERED", "reason": "DOCKER_SBOM_UNAVAILABLE"}
    secret_value = "fixture-secret-" + secrets.token_hex(16)
    admission_scope = "guardian.local.linux-worker.v3"
    receipt_key = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(prefix="guardian-durable-state-v3-") as state_temp:
        state_path = Path(state_temp) / "security-state.sqlite3"
        state = DurableSecurityState(state_path, admission_scope, admission_capacity=64, challenge_capacity=64)
        session_id = "pilot-session-" + secrets.token_hex(16)
        tool_fixture = Fixture()
        tool_request = copy.deepcopy(tool_fixture.request)
        tool_request["tool"] = "admin.shell"
        tool_substitution = _authorization_substitution(
            tool_fixture,
            tool_request,
            state,
            admission_scope,
            "tool-substitution-" + secrets.token_hex(8),
            image,
        )
        destination_fixture = Fixture()
        destination_request = copy.deepcopy(destination_fixture.request)
        destination_request["destination"] = "https://forbidden.local/mcp"
        destination_substitution = _authorization_substitution(
            destination_fixture,
            destination_request,
            state,
            admission_scope,
            "destination-substitution-" + secrets.token_hex(8),
            image,
        )
        safe = Fixture(body={"mode": "safe", "payload": "local"})
        safe_grant = _issue(
            safe,
            "grant-safe-" + secrets.token_hex(8),
            state,
            admission_scope,
            session_id,
            image,
        )
        positive = _execute(
            image, safe, safe_grant, receipt_key, secret_value, "positive", state, admission_scope, session_id
        )
        sequential_replay = _execute(
            image, safe, safe_grant, receipt_key, secret_value, "sequential-replay", state, admission_scope, session_id
        )
        restarted_state = DurableSecurityState(state_path, admission_scope, admission_capacity=64, challenge_capacity=64)
        restart_replay = _execute(
            image,
            safe,
            safe_grant,
            receipt_key,
            secret_value,
            "restart-replay",
            restarted_state,
            admission_scope,
            "restarted-session-" + secrets.token_hex(16),
        )

        concurrent_fixture = Fixture(body={"mode": "safe", "payload": "concurrent"})
        concurrent_grant = _issue(
            concurrent_fixture,
            "grant-concurrent-" + secrets.token_hex(8),
            state,
            admission_scope,
            session_id,
            image,
        )
        with ThreadPoolExecutor(max_workers=4) as pool:
            concurrent_results = list(
                pool.map(
                    lambda index: _execute(
                        image,
                        concurrent_fixture,
                        concurrent_grant,
                        receipt_key,
                        secret_value,
                        "concurrent-" + str(index),
                        state,
                        admission_scope,
                        session_id,
                    ),
                    range(4),
                )
            )

        orphan = Fixture(body={"mode": "safe", "payload": "orphaned-admission"})
        orphan_grant = _issue(
            orphan,
            "grant-orphan-" + secrets.token_hex(8),
            state,
            admission_scope,
            session_id,
            image,
        )
        orphan_payload, orphan_digest = verify_scoped_execution_grant(
            orphan_grant,
            orphan.grant_key.public_key(),
            orphan.now,
            admission_scope,
            orphan.binding,
            WORKER_SHA256,
            image,
            orphan.trust.version,
        )
        state.prepare_admission(
            orphan_payload["grant_id"],
            orphan_digest,
            orphan_payload["binding_sha256"],
            "terminated-session",
            "attempt-before-restart",
            orphan.now,
            orphan_payload["expires_at"],
        )
        orphan_restart = _execute(
            image,
            orphan,
            orphan_grant,
            receipt_key,
            secret_value,
            "orphan-restart",
            restarted_state,
            admission_scope,
            "replacement-session",
        )
        restarted_state.require_recovery(
            orphan_payload["grant_id"],
            orphan_digest,
            orphan_payload["binding_sha256"],
            orphan.now,
        )
        orphan_record = restarted_state.read_admission(orphan_payload["grant_id"])

        mutated_request_fixture = copy.copy(safe)
        mutated_request_fixture.request = copy.deepcopy(safe.request)
        mutated_request_fixture.request["body"]["payload"] = "mutated"
        mutated_request = _execute(
            image,
            mutated_request_fixture,
            safe_grant,
            receipt_key,
            secret_value,
            "mutated-request",
            state,
            admission_scope,
            session_id,
        )
        tampered_grant = copy.deepcopy(safe_grant)
        tampered_grant["payload"]["subject"] = "attacker"
        tampered = _execute(
            image, safe, tampered_grant, receipt_key, secret_value, "tampered-grant", state, admission_scope, session_id
        )
        crash = Fixture(body={"mode": "crash", "payload": "local"})
        crash_grant = _issue(
            crash,
            "grant-crash-" + secrets.token_hex(8),
            state,
            admission_scope,
            session_id,
            image,
        )
        crash_result = _execute(
            image, crash, crash_grant, receipt_key, secret_value, "crash", state, admission_scope, session_id
        )
        recovery = Fixture(body={"mode": "safe", "payload": "recovery"})
        recovery_grant = _issue(
            recovery,
            "grant-recovery-" + secrets.token_hex(8),
            state,
            admission_scope,
            session_id,
            image,
        )
        recovery_result = _execute(
            image,
            recovery,
            recovery_grant,
            receipt_key,
            secret_value,
            "recovery",
            state,
            admission_scope,
            session_id,
        )
    independent_receipt = verify_execution_evidence(
        safe.request,
        safe_grant,
        positive.get("receipt"),
        safe.grant_key.public_key(),
        receipt_key.public_key(),
        admission_scope,
        WORKER_SHA256,
        image,
        safe.trust.version,
    )
    _write_json(out.parent / "positive-request.json", safe.request)
    _write_json(out.parent / "positive-grant.json", safe_grant)
    _write_json(out.parent / "positive-receipt.json", positive.get("receipt"))
    _write_json(out.parent / "independent-recompute.json", independent_receipt)
    (out.parent / "grant-public-key.pem").write_bytes(
        safe.grant_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    (out.parent / "receipt-public-key.pem").write_bytes(
        receipt_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    observation = positive.get("observation", {})
    concurrent_executions = sum(
        row.get("admission") == "PREPARED_DURABLE" and row.get("execution_state") == "EXECUTED"
        for row in concurrent_results
    )
    concurrent_refusals = sum(row.get("container_started") is False for row in concurrent_results)
    checks = {
        "signed_grant_prepared": positive.get("admission") == "PREPARED_DURABLE",
        "durable_outcome_executed": positive.get("execution_state") == "EXECUTED",
        "sequential_replay_no_container": sequential_replay.get("container_started") is False and sequential_replay.get("reason") == "GRANT_REPLAY_COMMITTED",
        "restart_replay_no_container": restart_replay.get("container_started") is False and restart_replay.get("reason") == "GRANT_REPLAY_COMMITTED",
        "concurrent_exactly_one_admitted": concurrent_executions == 1 and concurrent_refusals == 3,
        "orphan_restart_no_container": orphan_restart.get("container_started") is False and orphan_restart.get("reason") == "GRANT_REPLAY_PREPARED",
        "orphan_recovery_state": orphan_record.get("state") == "RECOVERY_REQUIRED",
        "mutated_request_no_container": mutated_request.get("container_started") is False and mutated_request.get("reason") == "GRANT_REQUEST_BINDING",
        "tampered_grant_no_container": tampered.get("container_started") is False and tampered.get("reason") == "GRANT_SIGNATURE",
        "tool_substitution_refused": tool_substitution.get("grant_issued") is False,
        "destination_substitution_refused": destination_substitution.get("grant_issued") is False,
        "receipt_independently_recomputed": independent_receipt.get("verified") is True and independent_receipt.get("classification") == "EXECUTED",
        "positive_exit": positive.get("exit_code") == 0 and not positive.get("timed_out"),
        "crash_observed": crash_result.get("exit_code") == 42 and crash_result.get("execution_state") == "EXECUTED",
        "recovery_exit": recovery_result.get("exit_code") == 0 and recovery_result.get("execution_state") == "EXECUTED",
        "non_root": observation.get("non_root_uid") == 65534,
        "no_new_privileges": observation.get("no_new_privs") is True,
        "zero_capabilities": observation.get("cap_eff") == "0000000000000000",
        "seccomp_active": observation.get("seccomp") == "2",
        "read_only_root_effect": observation.get("filesystem_root") == "WRITE_DENIED_OBSERVED",
        "bounded_scratch_effect": observation.get("scratch_limit") == "ENOSPC_OBSERVED",
        "network_none_effect": observation.get("network_egress") == "DENIED_OBSERVED" and observation.get("interfaces") == "lo,",
        "host_secret_absent": observation.get("host_secret") == "ABSENT_OBSERVED" and positive.get("secret_absent_from_output") is True,
        "host_secret_unchanged": positive.get("secret_unchanged") is True,
        "pids_limit": observation.get("pids_max") == "16",
        "memory_limit": observation.get("memory_max") == "67108864",
        "cpu_limit": observation.get("cpu_max") == "50000 100000",
        "nofile_limit": observation.get("nofile_limit") == "64",
    }
    report.update(
        status="VERIFIED_LOCAL_PILOT" if all(checks.values()) else "HOLD",
        checks=checks,
        positive=positive,
        sequential_replay=sequential_replay,
        restart_replay=restart_replay,
        concurrent_replay=concurrent_results,
        orphan_restart=orphan_restart,
        mutated_request=mutated_request,
        tampered_grant=tampered,
        tool_substitution=tool_substitution,
        destination_substitution=destination_substitution,
        independent_receipt=independent_receipt,
        crash=crash_result,
        recovery=recovery_result,
        authenticated_invocation="VERIFIED_LOCAL_DISPOSABLE",
        durable_admission="VERIFIED_LOCAL_SQLITE_ATOMIC",
        exactly_once_execution="NOT_CLAIMED",
        production_authenticated_invocation="NOT_COVERED",
        production_rootless_isolation="NOT_COVERED",
    )
    out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii", newline="\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--image",
        default=os.environ.get("GUARDIAN_LINUX_V3_IMAGE", os.environ.get("GUARDIAN_LINUX_V2_IMAGE", "")),
    )
    args = parser.parse_args(argv)
    if not args.image:
        result = {
            "schema": "guardian.linux-isolated-worker-result.v3",
            "status": "NOT_COVERED",
            "reason": "NO_PINNED_LOCAL_IMAGE",
            "rootless_user_namespace": _rootless_probe(),
            "rootless_container_daemon": "NOT_COVERED",
            "production_ready": False,
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="ascii", newline="\n")
        print(json.dumps(result, sort_keys=True))
        return 0
    result = run(args.out, args.image)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"VERIFIED_LOCAL_PILOT", "NOT_COVERED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
