"""Execute one repository Python validator through the proven two-stage token reduction.

The elevated hosted caller creates a SAFER NormalUser/medium-integrity stage.
That stage creates a direct LUA restriction of its own primary token, validates
the final token before ResumeThread, writes a bounded proof, and only then runs
the requested repository validator.  No account, existing ACL, UAC setting, or
privilege is changed and no environment values are recorded.
"""

import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import runpy
import sys
from ctypes import wintypes as w

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guardian import windows as win
from tools.ci_tokens import acceptable, inspect, reduced_token
from tools.restricted_startup_v1 import PrivateDesktop, launch, safer_normal_user_token, set_medium_integrity


def write(path, value):
    path = Path(path).resolve(); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, sort_keys=True, indent=2).encode("ascii") + b"\n")


def command_record(target, args):
    target = Path(target).resolve()
    if ROOT not in target.parents or target.suffix != ".py" or not target.is_file():
        raise ValueError("target must be an existing repository Python file")
    relative = target.relative_to(ROOT).as_posix()
    value = {"target": relative, "args": [str(value) for value in args]}
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    value["sha256"] = hashlib.sha256(canonical).hexdigest()
    value["target_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    return target, value


def safer_stage_acceptable(token, user_sha256):
    return (
        token["user_sha256"] == user_sha256
        and token["administrators_enabled"] is False
        and token["appcontainer"] is False
        and token["integrity_sid"] == "S-1-16-8192"
        and token["has_restrictions"] == 1
        and set(token["present_privileges"]) <= {"SeChangeNotifyPrivilege"}
    )


def wrapped_argv(target, args, marker):
    script = (
        "import pathlib,runpy,sys;"
        "pathlib.Path(" + repr(str(marker)) + ").write_bytes(b'started\\n');"
        "sys.argv=" + repr([str(target), *[str(value) for value in args]]) + ";"
        "runpy.run_path(" + repr(str(target)) + ",run_name='__main__')"
    )
    return [sys.executable, "-I", "-S", "-B", "-c", script]


def stage(out, proof, marker, timeout, target, target_args):
    out = Path(out).resolve(); proof = Path(proof).resolve(); marker = Path(marker).resolve()
    record = {"schema": "guardian.restricted-exec-stage.v1", "status": "CONTROL_BROKEN"}
    current = w.HANDLE(); final = None
    win.check(win.open_token(win.current(), 0x8B, c.byref(current)))
    try:
        before = inspect(current); record["stage_token"] = before
        if before["administrators_enabled"] or before["integrity_sid"] != "S-1-16-8192" or set(before["present_privileges"]) > {"SeChangeNotifyPrivilege"}:
            record["reason"] = "STAGE_TOKEN_PREDICATES_FAILED"; return record
        final = reduced_token(current)
        observed = inspect(final); record["final_token"] = observed
        record["final_token_acceptable"] = acceptable(observed, before["user_sha256"])
        if not record["final_token_acceptable"]:
            record["reason"] = "FINAL_TOKEN_PREDICATES_FAILED"; return record
        resolved, command = command_record(target, target_args)
        proof_record = {
            "schema": "guardian.restricted-exec-proof.v1",
            "status": "PRE_RESUME_TOKEN_VERIFIED",
            "final_token": observed,
            "command": command,
            "manual_privilege_adjustment": False,
            "existing_acl_modified": False,
        }
        if proof.exists():
            raise ValueError("fresh startup proof required")
        write(proof, proof_record)
        row = launch(
            "restricted-validator", "CreateProcessAsUserW", final, before, marker,
            wrapped_argv(resolved, target_args, marker), timeout=timeout,
        )
        record["launch"] = row
        record["parent_after"] = inspect(current)
        record["parent_token_unchanged"] = record["parent_after"] == before
        if row.get("marker") == "started\n" and row.get("child_acceptable") and record["parent_token_unchanged"]:
            record.update(status="EXECUTED", target_exit_code=row.get("exit_code"))
        else:
            record["reason"] = "FINAL_VALIDATOR_STARTUP_NOT_OBSERVED"
        return record
    finally:
        for handle in (final, current):
            if handle:
                win.close(handle)
        write(out, record)


def top(out, proof, timeout, target, target_args):
    out = Path(out).resolve(); proof = Path(proof).resolve()
    if out.exists() or proof.exists():
        raise ValueError("fresh launcher evidence paths required")
    record = {"schema": "guardian.restricted-exec.v1", "status": "CONTROL_BROKEN"}
    current = w.HANDLE(); safer = None; private = None
    win.check(win.open_token(win.current(), 0x8B, c.byref(current)))
    try:
        before = inspect(current); record["parent_before"] = before
        if not before["elevated"]:
            record["reason"] = "ELEVATED_CALLER_REQUIRED"; return record
        safer = safer_normal_user_token(current); set_medium_integrity(safer)
        stage_token = inspect(safer); record["stage_token"] = stage_token
        record["stage_token_acceptable"] = safer_stage_acceptable(stage_token, before["user_sha256"])
        if not record["stage_token_acceptable"]:
            record["reason"] = "SAFER_STAGE_PREDICATES_FAILED"; return record
        private = PrivateDesktop(win.token_info()["user_sid"])
        stage_out = out.with_suffix(".stage.json"); marker = out.with_suffix(".marker")
        argv = [
            sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
            "--stage", "--out", str(stage_out), "--proof", str(proof),
            "--marker", str(marker), "--timeout", str(timeout), str(target), *target_args,
        ]
        row = launch(
            "safer-stage", "CreateProcessAsUserW", safer, before, marker, argv,
            desktop=private.qualified_name, timeout=timeout + 30, expected_token=stage_token,
        )
        record["stage_launch"] = row
        record["parent_after"] = inspect(current)
        record["parent_token_unchanged"] = record["parent_after"] == before
        if stage_out.exists():
            record["stage"] = json.loads(stage_out.read_bytes())
        stage_record = record.get("stage", {})
        if (row.get("marker") == "started\n" and row.get("child_matches_expected")
                and record["parent_token_unchanged"] and stage_record.get("status") == "EXECUTED"):
            record.update(status="EXECUTED", target_exit_code=stage_record.get("target_exit_code"))
        else:
            record["reason"] = "RESTRICTED_STAGE_CONTROL_BROKEN"
        return record
    finally:
        if private:
            private.close()
        for handle in (safer, current):
            if handle:
                win.close(handle)
        write(out, record)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--marker", type=Path)
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("target", type=Path)
    parser.add_argument("target_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.timeout < 1 or args.timeout > 2700:
        raise ValueError("timeout outside bounded range")
    if args.stage:
        if args.marker is None:
            raise ValueError("stage marker required")
        result = stage(args.out, args.proof, args.marker, args.timeout, args.target, args.target_args)
    else:
        result = top(args.out, args.proof, args.timeout, args.target, args.target_args)
    if result.get("status") != "EXECUTED":
        return 2
    return int(result.get("target_exit_code", 2))


if __name__ == "__main__":
    raise SystemExit(main())
