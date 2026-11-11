"""Exercise restricted-token child startup without changing accounts or ACLs.

The primary path uses CreateProcessAsUserW with a restricted version of the
caller's own primary token.  Microsoft documents that this case does not need
SeAssignPrimaryTokenPrivilege.  Windows may enable an already-present required
privilege only for the duration of the API call; this probe never calls
AdjustTokenPrivileges and verifies that the caller token is unchanged after
every attempt.
"""

import argparse
import ctypes as c
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from ctypes import wintypes as w

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guardian import windows as win
from tools.ci_tokens import acceptable, inspect, reduced_token


def environment():
    names = (
        "SystemRoot", "WINDIR", "SystemDrive", "USERPROFILE", "LOCALAPPDATA",
        "APPDATA", "ProgramFiles", "ProgramData", "COMSPEC", "PATH", "TEMP", "TMP",
    )
    values = {name: os.environ[name] for name in names if name in os.environ}
    values["PYTHONDONTWRITEBYTECODE"] = "1"
    return c.create_unicode_buffer(
        "\0".join(key + "=" + values[key] for key in sorted(values, key=str.upper)) + "\0\0"
    )


def launch(api_name, token, parent, marker):
    if marker.exists():
        raise ValueError("fresh startup marker required")
    snippet = "import pathlib;pathlib.Path(" + repr(str(marker)) + ").write_bytes(b'started\\n')"
    argv = [sys.executable, "-I", "-S", "-B", "-c", snippet]
    command = c.create_unicode_buffer(subprocess.list2cmdline(argv))
    si = win.STARTUPINFO(); si.cb = c.sizeof(si)
    pi = win.PROCESSINFO()
    flags = 0x00000004 | 0x00000400 | 0x08000000
    row = {
        "api": api_name,
        "argv": argv,
        "created_suspended": False,
        "manual_privilege_adjustment": False,
    }
    started = time.perf_counter()
    try:
        if api_name == "CreateProcessAsUserW":
            create = win.api(
                win.a, "CreateProcessAsUserW", w.BOOL, w.HANDLE, w.LPCWSTR, w.LPWSTR,
                win.P, win.P, w.BOOL, w.DWORD, win.P, w.LPCWSTR,
                c.POINTER(win.STARTUPINFO), c.POINTER(win.PROCESSINFO),
            )
            ok = create(token, sys.executable, command, None, None, False, flags,
                        environment(), str(ROOT), c.byref(si), c.byref(pi))
        elif api_name == "CreateProcessWithTokenW":
            create = win.api(
                win.a, "CreateProcessWithTokenW", w.BOOL, w.HANDLE, w.DWORD,
                w.LPCWSTR, w.LPWSTR, w.DWORD, win.P, w.LPCWSTR,
                c.POINTER(win.STARTUPINFO), c.POINTER(win.PROCESSINFO),
            )
            ok = create(token, 0, sys.executable, command, flags, environment(),
                        str(ROOT), c.byref(si), c.byref(pi))
        else:
            raise ValueError("unsupported launch API")
        if not ok:
            error = c.get_last_error()
            row.update(created=False, winerror=error, error=str(c.WinError(error)))
            return row
        row.update(created=True, created_suspended=True, pid=int(pi.dwProcessId))
        child = w.HANDLE(); win.check(win.open_token(pi.hProcess, 8, c.byref(child)))
        try:
            row["child_token"] = inspect(child)
        finally:
            win.close(child)
        row["child_acceptable"] = acceptable(row["child_token"], parent["user_sha256"])
        if not row["child_acceptable"]:
            row["error"] = "CHILD_TOKEN_CONTROL_BROKEN"
            return row
        resumed = win.api(win.k, "ResumeThread", w.DWORD, w.HANDLE)(pi.hThread)
        row["resume_previous_count"] = int(resumed)
        if resumed == 0xFFFFFFFF:
            error = c.get_last_error()
            row.update(winerror=error, error=str(c.WinError(error)))
            return row
        row["wait"] = int(win.api(win.k, "WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)(pi.hProcess, 20000))
        code = w.DWORD()
        win.check(win.api(win.k, "GetExitCodeProcess", w.BOOL, w.HANDLE, c.POINTER(w.DWORD))(pi.hProcess, c.byref(code)))
        row["exit_code"] = int(code.value)
        row["marker"] = marker.read_text(encoding="ascii") if marker.exists() else None
        row["started"] = row["wait"] == 0 and row["exit_code"] == 0 and row["marker"] == "started\n"
        return row
    except (OSError, RuntimeError, ValueError) as exc:
        row["error"] = type(exc).__name__ + ": " + str(exc)
        return row
    finally:
        if pi.hProcess:
            if win.api(win.k, "WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)(pi.hProcess, 0) != 0:
                win.api(win.k, "TerminateProcess", w.BOOL, w.HANDLE, w.UINT)(pi.hProcess, 97)
                win.api(win.k, "WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)(pi.hProcess, 5000)
            win.close(pi.hProcess)
        if pi.hThread:
            win.close(pi.hThread)
        row["seconds"] = time.perf_counter() - started


def run(out):
    out = Path(out).resolve(); out.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "schema": "guardian.restricted-startup.v1",
        "status": "NOT_COVERED",
        "manual_privilege_adjustment": False,
        "attempts": [],
    }
    current = w.HANDLE(); restricted = None; launch_token = w.HANDLE()
    win.check(win.open_token(win.current(), 0x8B, c.byref(current)))
    try:
        before = inspect(current); record["parent_before"] = before
        if not before["elevated"]:
            record["reason"] = "REQUIRES_ALREADY_ELEVATED_HOSTED_CALLER"
            return record
        restricted = reduced_token(current)
        win.check(win.api(
            win.a, "DuplicateTokenEx", w.BOOL, w.HANDLE, w.DWORD, win.P,
            c.c_int, c.c_int, c.POINTER(w.HANDLE),
        )(restricted, 0x18B, None, 2, 1, c.byref(launch_token)))
        record["launch_token"] = inspect(launch_token)
        record["launch_token_acceptable"] = acceptable(record["launch_token"], before["user_sha256"])
        if not record["launch_token_acceptable"]:
            record.update(status="CONTROL_BROKEN", reason="RESTRICTED_TOKEN_PREDICATES_FAILED")
            return record
        for name in ("CreateProcessAsUserW", "CreateProcessWithTokenW"):
            marker = out.with_suffix("." + name + ".marker")
            row = launch(name, launch_token, before, marker)
            after = inspect(current)
            row["parent_token_unchanged"] = after == before
            record["attempts"].append(row)
        primary = record["attempts"][0]
        record["parent_after"] = inspect(current)
        record["parent_token_unchanged"] = record["parent_after"] == before
        if primary.get("started") and primary.get("child_acceptable") and record["parent_token_unchanged"]:
            record["status"] = "VERIFIED"
        elif primary.get("created") and not primary.get("child_acceptable", False):
            record.update(status="CONTROL_BROKEN", reason="CHILD_TOKEN_PREDICATES_FAILED")
        else:
            record["reason"] = "RESTRICTED_CHILD_STARTUP_NOT_OBSERVED"
        return record
    finally:
        for handle in (launch_token, restricted, current):
            if handle:
                win.close(handle)
        out.write_bytes(json.dumps(record, sort_keys=True, indent=2).encode("ascii") + b"\n")
        print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(); run(args.out)
