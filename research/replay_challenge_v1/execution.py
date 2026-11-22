"""Durably admitted local Docker execution; no exactly-once claim."""

import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

from research.auth_gateway_v1.canonical import canonical_json_bytes
from research.auth_gateway_v1.errors import SecurityError
from research.auth_gateway_v1.model import RequestBinding

from .receipt import issue_execution_receipt
from .scoped_grant import verify_scoped_execution_grant


def execute_confined(
    image,
    request,
    public_key,
    grant,
    receipt_private_key,
    secret_value,
    label,
    durable_state,
    admission_scope,
    trust_version,
    session_id,
    now,
    worker_path,
    runner,
    root,
):
    binding = RequestBinding.from_request(request)
    worker_sha256 = hashlib.sha256(Path(worker_path).read_bytes()).hexdigest()
    try:
        payload, grant_sha256 = verify_scoped_execution_grant(
            grant,
            public_key,
            now,
            admission_scope,
            binding,
            worker_sha256,
            image,
            trust_version,
        )
        claim = durable_state.prepare_admission(
            payload["grant_id"],
            grant_sha256,
            payload["binding_sha256"],
            session_id,
            "attempt-" + secrets.token_hex(16),
            now,
            payload["expires_at"],
        )
    except SecurityError as error:
        return {
            "label": label,
            "admission": "REFUSED",
            "reason": error.code,
            "container_started": False,
        }
    with tempfile.TemporaryDirectory(prefix="guardian-linux-v3-") as temp:
        temp_root = Path(temp)
        input_folder = temp_root / "input"
        input_folder.mkdir()
        host_secret = temp_root / "host-secret.txt"
        host_secret.write_text(secret_value, encoding="ascii", newline="\n")
        secret_before = hashlib.sha256(host_secret.read_bytes()).hexdigest()
        request_bytes = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        (input_folder / "request.json").write_bytes(request_bytes)
        (input_folder / "worker.sh").write_bytes(Path(worker_path).read_bytes())
        cidfile = temp_root / "container.cid"
        mount = str(input_folder.resolve()) + ":/input:ro"
        argv = [
            "docker",
            "run",
            "--rm",
            "--cidfile",
            str(cidfile),
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
            process = runner(argv, timeout=45, cwd=root)
            timed_out = False
            launch_error = None
        except subprocess.TimeoutExpired as error:
            process = error
            timed_out = True
            launch_error = None
        except OSError as error:
            process = None
            timed_out = False
            launch_error = type(error).__name__
        container_id = None
        start_observation_error = None
        if cidfile.is_file():
            try:
                candidate = cidfile.read_text(encoding="ascii").strip().lower()
            except (OSError, UnicodeError):
                candidate = ""
                start_observation_error = "CONTAINER_IDENTITY_UNREADABLE"
            if re.fullmatch(r"[0-9a-f]{64}", candidate):
                container_id = candidate
            elif start_observation_error is None:
                start_observation_error = "CONTAINER_IDENTITY_INVALID"
        elif process is not None:
            start_observation_error = "CONTAINER_START_NOT_OBSERVED"
        container_started = container_id is not None
        secret_after = hashlib.sha256(host_secret.read_bytes()).hexdigest()
        stdout_bytes = b"" if process is None else (process.stdout or b"")
        stderr_bytes = b"" if process is None else (process.stderr or b"")
        if type(stdout_bytes) is str:
            stdout_bytes = stdout_bytes.encode("utf-8", errors="replace")
        if type(stderr_bytes) is str:
            stderr_bytes = stderr_bytes.encode("utf-8", errors="replace")
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        exit_code = None if timed_out or process is None else process.returncode
        outcome = {
            "grant_id": payload["grant_id"],
            "binding_sha256": payload["binding_sha256"],
            "timed_out": timed_out,
            "launch_error": launch_error,
            "start_observation_error": start_observation_error,
            "container_id_sha256": None if container_id is None else hashlib.sha256(container_id.encode("ascii")).hexdigest(),
            "exit_code": exit_code,
            "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
        }
        outcome_sha256 = hashlib.sha256(canonical_json_bytes(outcome)).hexdigest()
        execution_state = "EXECUTED"
        lifecycle = "COMMITTED"
        transition_error = None
        try:
            if timed_out:
                execution_state = "RECOVERY_REQUIRED"
                lifecycle = "RECOVERY_REQUIRED"
                durable_state.mark_recovery_required(claim, now, outcome_sha256)
            elif launch_error is not None:
                execution_state = "ABORTED"
                lifecycle = "ABORTED"
                durable_state.mark_aborted(claim, now, outcome_sha256)
            elif not container_started:
                execution_state = "RECOVERY_REQUIRED"
                lifecycle = "RECOVERY_REQUIRED"
                durable_state.mark_recovery_required(claim, now, outcome_sha256)
            else:
                durable_state.mark_committed(claim, now, outcome_sha256, exit_code)
        except SecurityError as error:
            execution_state = "RECOVERY_REQUIRED"
            lifecycle = "RECOVERY_REQUIRED"
            transition_error = error.code
        value = {
            "label": label,
            "admission": "PREPARED_DURABLE",
            "lifecycle": lifecycle,
            "execution_state": execution_state,
            "container_started": container_started,
            "container_id_sha256": outcome["container_id_sha256"],
            "start_observation_error": start_observation_error,
            "binding_sha256": payload["binding_sha256"],
            "grant_sha256": grant_sha256,
            "outcome_sha256": outcome_sha256,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "launch_error": launch_error,
            "transition_error": transition_error,
            "stdout_sha256": outcome["stdout_sha256"],
            "stderr_sha256": outcome["stderr_sha256"],
            "secret_before_sha256": secret_before,
            "secret_after_sha256": secret_after,
            "secret_unchanged": secret_before == secret_after,
            "secret_absent_from_output": secret_value not in stdout and secret_value not in stderr,
            "argv_security_flags": [
                "pull=never",
                "network=none",
                "read_only=true",
                "cap_drop=ALL",
                "no_new_privileges=true",
                "pids_limit=16",
                "memory=64m",
                "memory_swap=64m",
                "cpus=0.5",
                "user=65534:65534",
                "nofile=64:64",
                "tmpfs=/tmp:rw,noexec,nosuid,nodev,size=8m",
                "input_mount=read_only",
                "entrypoint=/bin/sh",
            ],
            "exactly_once_claimed": False,
        }
        try:
            value["receipt"] = issue_execution_receipt(
                receipt_private_key,
                claim,
                grant,
                grant_sha256,
                payload,
                lifecycle,
                now,
                container_started,
                outcome,
                outcome_sha256,
            )
            value["receipt_status"] = "SIGNED"
        except (SecurityError, ValueError, TypeError) as error:
            value["receipt_status"] = "UNVERIFIABLE"
            value["receipt_error"] = error.code if isinstance(error, SecurityError) else type(error).__name__
        if not timed_out and container_started and exit_code == 0:
            try:
                value["observation"] = json.loads(stdout)
            except json.JSONDecodeError:
                value["parse_error"] = True
        return value
