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
from tools.ci_tokens import SIDATTR, acceptable, inspect, reduced_token


class SECURITY_ATTRIBUTES(c.Structure):
    _fields_ = [("nLength", w.DWORD), ("lpSecurityDescriptor", win.P), ("bInheritHandle", w.BOOL)]


class PrivateDesktop:
    """Disposable window station/desktop; never edits an existing object ACL."""

    def __init__(self, user_sid):
        self.user = c.WinDLL("user32", use_last_error=True)
        self.station = w.HANDLE(); self.desktop = w.HANDLE(); self.sd = win.P()
        self.station_name = "Guardian-" + str(os.getpid()) + "-" + str(time.time_ns())
        self.desktop_name = "Worker"
        convert = win.api(
            win.a, "ConvertStringSecurityDescriptorToSecurityDescriptorW", w.BOOL,
            w.LPCWSTR, w.DWORD, c.POINTER(win.P), win.P,
        )
        win.check(convert("D:P(A;;GA;;;SY)(A;;GA;;;" + user_sid + ")", 1, c.byref(self.sd), None))
        sa = SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES), self.sd, False)
        create_station = win.api(
            self.user, "CreateWindowStationW", w.HANDLE, w.LPCWSTR, w.DWORD,
            w.DWORD, c.POINTER(SECURITY_ATTRIBUTES),
        )
        create_desktop = win.api(
            self.user, "CreateDesktopW", w.HANDLE, w.LPCWSTR, w.LPCWSTR, win.P,
            w.DWORD, w.DWORD, c.POINTER(SECURITY_ATTRIBUTES),
        )
        get_station = win.api(self.user, "GetProcessWindowStation", w.HANDLE)
        set_station = win.api(self.user, "SetProcessWindowStation", w.BOOL, w.HANDLE)
        original = get_station(); win.check(original)
        switched = False
        try:
            self.station = create_station(self.station_name, 0, 0x000F037F, c.byref(sa))
            win.check(self.station)
            win.check(set_station(self.station)); switched = True
            self.desktop = create_desktop(self.desktop_name, None, None, 0, 0x000F01FF, c.byref(sa))
            win.check(self.desktop)
        except Exception:
            if switched:
                set_station(original); switched = False
            if self.desktop:
                win.api(self.user, "CloseDesktop", w.BOOL, w.HANDLE)(self.desktop); self.desktop = None
            if self.station:
                win.api(self.user, "CloseWindowStation", w.BOOL, w.HANDLE)(self.station); self.station = None
            if self.sd:
                win.local_free(self.sd); self.sd = None
            raise
        finally:
            if switched:
                win.check(set_station(original))

    @property
    def qualified_name(self):
        return self.station_name + "\\" + self.desktop_name

    def close(self):
        if self.desktop:
            win.check(win.api(self.user, "CloseDesktop", w.BOOL, w.HANDLE)(self.desktop)); self.desktop = None
        if self.station:
            win.check(win.api(self.user, "CloseWindowStation", w.BOOL, w.HANDLE)(self.station)); self.station = None
        if self.sd:
            win.local_free(self.sd); self.sd = None


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


def safer_normal_user_token(original):
    """Return the documented SAFER NormalUser restriction without inert flags."""
    level = w.HANDLE(); token = w.HANDLE()
    create = win.api(
        win.a, "SaferCreateLevel", w.BOOL, w.DWORD, w.DWORD, w.DWORD,
        c.POINTER(w.HANDLE), win.P,
    )
    compute = win.api(
        win.a, "SaferComputeTokenFromLevel", w.BOOL, w.HANDLE, w.HANDLE,
        c.POINTER(w.HANDLE), w.DWORD, win.P,
    )
    close_level = win.api(win.a, "SaferCloseLevel", w.BOOL, w.HANDLE)
    win.check(create(2, 0x00020000, 1, c.byref(level), None))
    try:
        win.check(compute(level, original, c.byref(token), 0, None))
        return token
    except Exception:
        if token:
            win.close(token)
        raise
    finally:
        win.check(close_level(level))


def set_medium_integrity(token):
    sid = win.P()
    try:
        win.check(win.api(
            win.a, "ConvertStringSidToSidW", w.BOOL, w.LPCWSTR, c.POINTER(win.P),
        )("S-1-16-8192", c.byref(sid)))
        label = SIDATTR(sid, 0x20)
        size = c.sizeof(label) + win.api(win.a, "GetLengthSid", w.DWORD, win.P)(sid)
        win.check(win.api(
            win.a, "SetTokenInformation", w.BOOL, w.HANDLE, c.c_int, win.P, w.DWORD,
        )(token, 25, c.byref(label), size))
    finally:
        if sid:
            win.local_free(sid)


def launch(name, api_name, token, parent, marker, argv, desktop=None, timeout=20, expected_token=None):
    if marker.exists():
        raise ValueError("fresh startup marker required")
    command = c.create_unicode_buffer(subprocess.list2cmdline(argv))
    si = win.STARTUPINFO(); si.cb = c.sizeof(si); si.lpDesktop = desktop
    pi = win.PROCESSINFO()
    flags = 0x00000004 | 0x00000400 | 0x08000000
    row = {
        "name": name,
        "api": api_name,
        "argv": argv,
        "desktop": desktop,
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
        elif api_name == "CreateProcessW":
            create = win.api(
                win.k, "CreateProcessW", w.BOOL, w.LPCWSTR, w.LPWSTR, win.P,
                win.P, w.BOOL, w.DWORD, win.P, w.LPCWSTR,
                c.POINTER(win.STARTUPINFO), c.POINTER(win.PROCESSINFO),
            )
            ok = create(sys.executable, command, None, None, False, flags,
                        environment(), str(ROOT), c.byref(si), c.byref(pi))
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
        row["child_matches_expected"] = row["child_token"] == expected_token if expected_token is not None else None
        if expected_token is None and not row["child_acceptable"]:
            row["error"] = "CHILD_TOKEN_CONTROL_BROKEN"
            return row
        if expected_token is not None and not row["child_matches_expected"]:
            row["error"] = "POSITIVE_CONTROL_TOKEN_MISMATCH"
            return row
        resumed = win.api(win.k, "ResumeThread", w.DWORD, w.HANDLE)(pi.hThread)
        row["resume_previous_count"] = int(resumed)
        if resumed == 0xFFFFFFFF:
            error = c.get_last_error()
            row.update(winerror=error, error=str(c.WinError(error)))
            return row
        row["wait"] = int(win.api(win.k, "WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)(pi.hProcess, timeout * 1000))
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
    current = w.HANDLE(); restricted = None; launch_token = w.HANDLE(); safer = None; safer_lua = None; private = None
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
        private = PrivateDesktop(win.token_info()["user_sid"])
        record["private_desktop"] = {
            "created": True,
            "qualified_name": private.qualified_name,
            "existing_acl_modified": False,
        }
        try:
            safer = safer_normal_user_token(current)
            record["safer_before_medium_integrity"] = inspect(safer)
            set_medium_integrity(safer)
            record["safer_normal_user_token"] = inspect(safer)
            record["safer_token_acceptable"] = acceptable(record["safer_normal_user_token"], before["user_sha256"])
            safer_lua = reduced_token(safer)
            record["safer_then_lua_token"] = inspect(safer_lua)
            record["safer_then_lua_acceptable"] = acceptable(record["safer_then_lua_token"], before["user_sha256"])
        except OSError as exc:
            record["safer_token_error"] = type(exc).__name__ + ": " + str(exc)
        cases = [
            ("parent-createprocess-positive-control", "CreateProcessW", current, None, 10, before),
            ("parent-createprocessasuser-diagnostic", "CreateProcessAsUserW", current, None, 10, before),
            ("python-inherited-desktop", "CreateProcessAsUserW", launch_token, None, 5, None),
            ("cmd-private-desktop", "CreateProcessAsUserW", launch_token, private.qualified_name, 10, None),
            ("python-private-desktop", "CreateProcessAsUserW", launch_token, private.qualified_name, 20, None),
            ("legacy-with-token", "CreateProcessWithTokenW", launch_token, None, 5, None),
        ]
        if safer:
            cases.insert(4, (
                "safer-python-private-desktop", "CreateProcessAsUserW", safer,
                private.qualified_name, 20, record["safer_normal_user_token"],
            ))
        if safer_lua and record.get("safer_then_lua_acceptable"):
            cases.insert(5, (
                "safer-lua-python-private-desktop", "CreateProcessAsUserW", safer_lua,
                private.qualified_name, 20, None,
            ))
        for name, api_name, token, desktop, timeout, expected in cases:
            marker = out.with_suffix("." + name + ".marker")
            if name.startswith("cmd"):
                argv = [os.environ["COMSPEC"], "/d", "/q", "/c", 'echo started>"' + str(marker) + '"']
            else:
                snippet = "import pathlib;pathlib.Path(" + repr(str(marker)) + ").write_bytes(b'started\\n')"
                argv = [sys.executable, "-I", "-S", "-B", "-c", snippet]
            row = launch(name, api_name, token, before, marker, argv, desktop, timeout, expected)
            after = inspect(current)
            row["parent_token_unchanged"] = after == before
            record["attempts"].append(row)
        safer_lua_primary = next((row for row in record["attempts"] if row["name"] == "safer-lua-python-private-desktop"), None)
        primary = safer_lua_primary if safer_lua_primary and safer_lua_primary.get("started") else next(
            row for row in record["attempts"] if row["name"] == "python-private-desktop"
        )
        positive = next(row for row in record["attempts"] if row["name"] == "parent-createprocess-positive-control")
        record["parent_after"] = inspect(current)
        record["parent_token_unchanged"] = record["parent_after"] == before
        record["positive_control"] = "PASS" if positive.get("started") and positive.get("child_matches_expected") else "CONTROL_BROKEN"
        if record["positive_control"] != "PASS":
            record.update(status="CONTROL_BROKEN", reason="CREATEPROCESSASUSER_POSITIVE_CONTROL_FAILED")
        elif primary.get("started") and primary.get("child_acceptable") and record["parent_token_unchanged"]:
            record["status"] = "VERIFIED"
        elif primary.get("created") and not primary.get("child_acceptable", False):
            record.update(status="CONTROL_BROKEN", reason="CHILD_TOKEN_PREDICATES_FAILED")
        else:
            record["reason"] = "RESTRICTED_CHILD_STARTUP_NOT_OBSERVED"
        return record
    finally:
        if private:
            private.close()
        for handle in (safer_lua, safer, launch_token, restricted, current):
            if handle:
                win.close(handle)
        out.write_bytes(json.dumps(record, sort_keys=True, indent=2).encode("ascii") + b"\n")
        print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(); run(args.out)
