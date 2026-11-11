"""Bounded Docker/WSL2 pilot using only an already-local image and TEST-NET."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
WORKER = Path(__file__).with_name("worker.sh")
EXPECTED_BEARER = "guardian-synthetic-bearer-v1"


def admit(bearer, request):
    if bearer != EXPECTED_BEARER:
        return {"admitted": False, "reason": "BEARER_REFUSED"}
    if type(request) is not dict or set(request) != {"schema", "origin", "action", "payload"}:
        return {"admitted": False, "reason": "REQUEST_SHAPE"}
    if request != {"schema": "guardian.linux-worker-request.v1", "origin": "synthetic", "action": "synthetic_echo", "payload": "safe"}:
        return {"admitted": False, "reason": "REQUEST_SCOPE"}
    return {"admitted": True, "reason": "SYNTHETIC_BEARER_AND_SCOPE"}


def _run(argv, timeout=30):
    return subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=timeout)


def _container(image, folder, request, bearer):
    admission = admit(bearer, request)
    if not admission["admitted"]:
        return {"admission": admission, "container_started": False, "exit_code": None}
    request_path = folder / "request.json"
    request_path.write_bytes(json.dumps(request, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
    worker_path = folder / "worker.sh"; worker_path.write_bytes(WORKER.read_bytes())
    mount = str(folder.resolve()) + ":/input:ro"
    argv = [
        "docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "16",
        "--memory", "64m", "--cpus", "0.5", "--user", "65534:65534",
        "--ulimit", "nofile=64:64", "--ulimit", "nproc=16:16",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m", "--volume", mount,
        "--entrypoint", "/bin/sh", image, "/input/worker.sh",
    ]
    process = _run(argv)
    value = {"admission": admission, "container_started": True, "argv": argv, "exit_code": process.returncode,
             "stdout": process.stdout.decode("utf-8", errors="replace"), "stderr": process.stderr.decode("utf-8", errors="replace")}
    if process.returncode == 0:
        try: value["observation"] = json.loads(value["stdout"])
        except json.JSONDecodeError: value["parse_error"] = True
    return value


def run(out, image):
    out = Path(out); out.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema": "guardian.linux-isolated-worker-result.v1", "scope": "LOCAL_SYNTHETIC_ONLY",
              "production_ready": False, "third_party_access": False, "image_pull": False}
    if os.name != "nt" and shutil.which("docker") is None:
        report.update(status="NOT_COVERED", reason="DOCKER_UNAVAILABLE")
    elif shutil.which("docker") is None:
        report.update(status="NOT_COVERED", reason="DOCKER_UNAVAILABLE")
    else:
        inspected = _run(["docker", "image", "inspect", image])
        if inspected.returncode:
            report.update(status="NOT_COVERED", reason="PINNED_LOCAL_IMAGE_UNAVAILABLE", image=image)
        else:
            image_data = json.loads(inspected.stdout)[0]
            security = _run(["docker", "info", "--format", "{{json .SecurityOptions}}"])
            options = security.stdout.decode(errors="replace").strip()
            report.update(image=image, image_id=image_data.get("Id"), repo_digests=image_data.get("RepoDigests", []),
                          image_inspect_sha256=hashlib.sha256(inspected.stdout).hexdigest(),
                          daemon_security_options=options, rootless_daemon="VERIFIED" if "rootless" in options.lower() else "NOT_COVERED")
            safe = {"schema": "guardian.linux-worker-request.v1", "origin": "synthetic", "action": "synthetic_echo", "payload": "safe"}
            unsafe = dict(safe, action="shell")
            with tempfile.TemporaryDirectory(prefix="guardian-linux-pilot-") as temp:
                folder = Path(temp)
                wrong_bearer = _container(image, folder, safe, "wrong-synthetic-token")
                invalid_request = _container(image, folder, unsafe, EXPECTED_BEARER)
                positive = _container(image, folder, safe, EXPECTED_BEARER)
                recovery = _container(image, folder, safe, EXPECTED_BEARER)
            observation = positive.get("observation", {})
            checks = {
                "wrong_bearer_no_container": not wrong_bearer["container_started"] and wrong_bearer["admission"]["reason"] == "BEARER_REFUSED",
                "invalid_request_no_container": not invalid_request["container_started"] and invalid_request["admission"]["reason"] == "REQUEST_SCOPE",
                "positive_exit": positive.get("exit_code") == 0,
                "recovery_exit": recovery.get("exit_code") == 0,
                "non_root": observation.get("non_root_uid") == 65534,
                "no_new_privileges": observation.get("no_new_privs") is True,
                "zero_capabilities": observation.get("cap_eff") == "0000000000000000",
                "read_only_root": observation.get("filesystem_root") == "READ_ONLY_OBSERVED",
                "writable_bounded_tmpfs": observation.get("tmpfs") == "WRITABLE_OBSERVED",
                "network_none_observed": observation.get("network_egress") == "DENIED_OBSERVED" and observation.get("interfaces") == "lo,",
                "pids_limit": observation.get("pids_max") == "16",
                "memory_limit": observation.get("memory_max") == "67108864",
                "cpu_limit": observation.get("cpu_max") == "50000 100000",
                "nofile_limit": observation.get("nofile_limit") == "64",
            }
            report.update(status="VERIFIED_LOCAL_PILOT" if all(checks.values()) else "HOLD",
                          equivalent_nonroot_container="VERIFIED" if all(checks.values()) else "REFUTED",
                          checks=checks, wrong_bearer=wrong_bearer, invalid_request=invalid_request,
                          positive=positive, recovery=recovery, live_infrastructure="NOT_ACCESSED",
                          authenticated_production_invocation="NOT_COVERED")
    out.write_bytes(json.dumps(report, sort_keys=True, indent=2).encode("ascii") + b"\n")
    print(json.dumps(report, sort_keys=True))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--image", default=os.environ.get("GUARDIAN_LINUX_PILOT_IMAGE", ""))
    args = parser.parse_args(argv)
    if not args.image:
        result = {"schema": "guardian.linux-isolated-worker-result.v1", "status": "NOT_COVERED", "reason": "NO_PINNED_LOCAL_IMAGE", "production_ready": False}
        args.out.parent.mkdir(parents=True, exist_ok=True); args.out.write_bytes(json.dumps(result, sort_keys=True, indent=2).encode() + b"\n"); print(json.dumps(result)); return 0
    result = run(args.out, args.image)
    return 0 if result["status"] in {"VERIFIED_LOCAL_PILOT", "NOT_COVERED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

