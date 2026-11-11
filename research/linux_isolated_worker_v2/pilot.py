"""Real local Docker/WSL containment campaign with signed grant admission."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

from research.auth_gateway_v1.errors import SecurityError
from research.auth_gateway_v1.gateway import GuardianAuthGateway
from research.auth_gateway_v1.grant import verify_execution_grant
from research.auth_gateway_v1.model import RequestBinding
from research.auth_gateway_v1.nonce import BoundedNonceStore
from tests_auth_v1.fixtures import Fixture


ROOT = Path(__file__).resolve().parents[2]
WORKER = Path(__file__).with_name("worker.sh")


def _run(argv, timeout=30, cwd=ROOT):
    return subprocess.run(argv, cwd=cwd, capture_output=True, timeout=timeout)


def _issue(fixture, grant_id):
    gateway = GuardianAuthGateway(
        fixture.trust,
        fixture.jwt_nonces,
        fixture.siwe_nonces,
        fixture.grant_key,
    )
    message, signature = fixture.make_siwe()
    return gateway.authorize_and_issue(
        fixture.make_jwt(),
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


def _execute(image, fixture, grant, secret_value, label):
    binding = RequestBinding.from_request(fixture.request)
    nonce_store = BoundedNonceStore(capacity=16, ttl_seconds=120)
    try:
        verified = verify_execution_grant(
            grant,
            fixture.grant_key.public_key(),
            nonce_store,
            fixture.now,
            binding,
        )
    except SecurityError as error:
        return {
            "label": label,
            "admission": "REFUSED",
            "reason": error.code,
            "container_started": False,
        }
    with tempfile.TemporaryDirectory(prefix="guardian-linux-v2-") as temp:
        root = Path(temp)
        input_folder = root / "input"
        input_folder.mkdir()
        host_secret = root / "host-secret.txt"
        host_secret.write_text(secret_value, encoding="ascii", newline="\n")
        secret_before = hashlib.sha256(host_secret.read_bytes()).hexdigest()
        request_bytes = json.dumps(
            fixture.request,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        (input_folder / "request.json").write_bytes(request_bytes)
        (input_folder / "worker.sh").write_bytes(WORKER.read_bytes())
        mount = str(input_folder.resolve()) + ":/input:ro"
        argv = [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "16",
            "--memory",
            "64m",
            "--memory-swap",
            "64m",
            "--cpus",
            "0.5",
            "--user",
            "65534:65534",
            "--ulimit",
            "nofile=64:64",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=8m",
            "--volume",
            mount,
            "--entrypoint",
            "/bin/sh",
            image,
            "/input/worker.sh",
        ]
        try:
            process = _run(argv, timeout=45)
            timed_out = False
        except subprocess.TimeoutExpired as error:
            process = error
            timed_out = True
        secret_after = hashlib.sha256(host_secret.read_bytes()).hexdigest()
        stdout_bytes = process.stdout or b""
        stderr_bytes = process.stderr or b""
        if type(stdout_bytes) is str:
            stdout_bytes = stdout_bytes.encode("utf-8", errors="replace")
        if type(stderr_bytes) is str:
            stderr_bytes = stderr_bytes.encode("utf-8", errors="replace")
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        value = {
            "label": label,
            "admission": "VERIFIED_SIGNED_GRANT",
            "container_started": True,
            "binding_sha256": verified["binding_sha256"],
            "exit_code": None if timed_out else process.returncode,
            "timed_out": timed_out,
            "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
            "secret_before_sha256": secret_before,
            "secret_after_sha256": secret_after,
            "secret_unchanged": secret_before == secret_after,
            "secret_absent_from_output": secret_value not in stdout and secret_value not in stderr,
            "argv_security_flags": argv[3:-3],
        }
        if not timed_out and process.returncode == 0:
            try:
                value["observation"] = json.loads(stdout)
            except json.JSONDecodeError:
                value["parse_error"] = True
        return value


def run(out, image):
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": "guardian.linux-isolated-worker-result.v2",
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
    security = _run(["docker", "info", "--format", "{{json .SecurityOptions}}"])
    security_options = security.stdout.decode("utf-8", errors="replace").strip()
    report.update(
        image=image,
        image_id=image_data.get("Id"),
        repo_digests=image_data.get("RepoDigests", []),
        image_inspect_sha256=hashlib.sha256(inspected.stdout).hexdigest(),
        daemon_security_options=security_options,
        rootless_container_daemon="VERIFIED" if "rootless" in security_options.lower() else "NOT_COVERED",
    )
    secret_value = "fixture-secret-" + secrets.token_hex(16)
    safe = Fixture(body={"mode": "safe", "payload": "local"})
    safe_grant = _issue(safe, "grant-safe-" + secrets.token_hex(8))
    positive = _execute(image, safe, safe_grant, secret_value, "positive")
    mutated_request_fixture = copy.copy(safe)
    mutated_request_fixture.request = copy.deepcopy(safe.request)
    mutated_request_fixture.request["body"]["payload"] = "mutated"
    mutated_request = _execute(image, mutated_request_fixture, safe_grant, secret_value, "mutated-request")
    tampered_grant = copy.deepcopy(safe_grant)
    tampered_grant["payload"]["subject"] = "attacker"
    tampered = _execute(image, safe, tampered_grant, secret_value, "tampered-grant")
    crash = Fixture(body={"mode": "crash", "payload": "local"})
    crash_result = _execute(image, crash, _issue(crash, "grant-crash-" + secrets.token_hex(8)), secret_value, "crash")
    recovery = Fixture(body={"mode": "safe", "payload": "recovery"})
    recovery_result = _execute(image, recovery, _issue(recovery, "grant-recovery-" + secrets.token_hex(8)), secret_value, "recovery")
    observation = positive.get("observation", {})
    checks = {
        "signed_grant_admitted": positive.get("admission") == "VERIFIED_SIGNED_GRANT",
        "mutated_request_no_container": mutated_request.get("container_started") is False and mutated_request.get("reason") == "GRANT_REQUEST_BINDING",
        "tampered_grant_no_container": tampered.get("container_started") is False and tampered.get("reason") == "GRANT_SIGNATURE",
        "positive_exit": positive.get("exit_code") == 0 and not positive.get("timed_out"),
        "crash_observed": crash_result.get("exit_code") == 42,
        "recovery_exit": recovery_result.get("exit_code") == 0,
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
        mutated_request=mutated_request,
        tampered_grant=tampered,
        crash=crash_result,
        recovery=recovery_result,
        authenticated_invocation="VERIFIED_LOCAL_DISPOSABLE",
        production_authenticated_invocation="NOT_COVERED",
        production_rootless_isolation="NOT_COVERED",
    )
    out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="ascii", newline="\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--image", default=os.environ.get("GUARDIAN_LINUX_V2_IMAGE", ""))
    args = parser.parse_args(argv)
    if not args.image:
        result = {
            "schema": "guardian.linux-isolated-worker-result.v2",
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
