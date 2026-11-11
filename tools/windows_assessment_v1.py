"""Independent bounded Windows assessment; never promotes NOT_COVERED to PASS."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def classify_startup(record):
    attempts = record.get("attempts", []) if type(record) is dict else []
    if any(row.get("exit_code") == 0 or row.get("marker") for row in attempts):
        return {"status": "VERIFIED", "root_cause": None}
    waits = [row.get("thread_query", {}).get("stdout", "") for row in attempts]
    if attempts and all(row.get("wait") == 258 and row.get("exit_code") == 259 for row in attempts) and all("WaitReason" in value and "10" in value for value in waits):
        return {"status": "NOT_COVERED", "root_cause": "CREATEPROCESSWITHTOKEN_CHILD_STALLED_IN_LPC_REPLY",
                "root_cause_scope": "Observed hosted symptom; internal Windows cause not established"}
    return {"status": "NOT_COVERED", "root_cause": "STARTUP_NOT_OBSERVED"}


def execute(name, argv, out, timeout):
    start = time.perf_counter()
    process = subprocess.run([sys.executable, "-B", *argv], cwd=ROOT, capture_output=True, timeout=timeout)
    (out / f"{name}.stdout").write_bytes(process.stdout)
    (out / f"{name}.stderr").write_bytes(process.stderr)
    return {"name": name, "argv": [sys.executable, "-B", *argv], "exit_code": process.returncode, "seconds": time.perf_counter() - start}


def named(cases, name):
    return next((row for row in cases if row.get("name") == name), None)


def campaign_control_causes(cases, scenarios):
    causes = []
    if not cases or any("control_broken" in row for row in cases):
        causes.append("V02_CAMPAIGN_CONTROL_BROKEN")
    if not scenarios or any("control_broken" in row for row in scenarios):
        causes.append("V04_CAMPAIGN_CONTROL_BROKEN")
    return causes


def run(out):
    out = Path(out).resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {"schema": "guardian.windows-security-assessment.v1", "platform": platform.platform(),
              "production_ready": False, "commands": [], "status": "NOT_COVERED"}
    if os.name == "nt":
        archive = ROOT / "build/runtime/python-3.12.10-embed-amd64.zip"
        lock = json.loads((ROOT / "runtime-lock.json").read_bytes())
        runtime_ok = archive.is_file() and hashlib.sha256(archive.read_bytes()).hexdigest() == lock.get("sha256")
        if not runtime_ok:
            report.update(
                status="HOLD",
                reason="PINNED_RUNTIME_MISSING_OR_MISMATCH",
                runtime_precondition="CONTROL_BROKEN",
                checks={
                    "appcontainer_identity": "NOT_COVERED",
                    "named_pipe_authentication": "NOT_COVERED",
                    "broker_permissions": "NOT_COVERED",
                    "file_access_bypass": "NOT_COVERED",
                    "execution_and_crash_recovery": "NOT_COVERED",
                    "restricted_token_child_startup": "NOT_COVERED",
                },
            )
            (out / "report.json").write_bytes(json.dumps(report, sort_keys=True, indent=2).encode("ascii") + b"\n")
            print(json.dumps(report, sort_keys=True))
            return report
        report["runtime_precondition"] = "VERIFIED_PINNED_SHA256"
    if os.name != "nt":
        report["reason"] = "WINDOWS_UNAVAILABLE"
    else:
        v02 = out / "v02"; v04 = out / "v04"; diagnostics = out / "diagnostics.json"
        report["commands"].append(execute("v02", ["tools/v02_campaign.py", "--out", str(v02)], out, 600))
        report["commands"].append(execute("v04", ["tools/v04_campaign.py", "--out", str(v04)], out, 600))
        report["commands"].append(execute("diagnostics", ["tools/ci_diagnostics.py", "--out", str(diagnostics)], out, 60))
        diagnostic = json.loads(diagnostics.read_bytes()) if diagnostics.exists() else {}
        startup_proof_path = getattr(run, "startup_proof", None)
        if startup_proof_path:
            proof = json.loads(Path(startup_proof_path).read_bytes())
            from guardian import windows as win
            from tools.ci_tokens import acceptable, inspect
            import ctypes as c
            from ctypes import wintypes as w
            token = w.HANDLE(); win.check(win.open_token(win.current(), 8, c.byref(token)))
            try:
                current_token = inspect(token)
            finally:
                win.close(token)
            proof_token = proof.get("final_token", {})
            if (proof.get("schema") == "guardian.restricted-exec-proof.v1"
                    and proof.get("status") == "PRE_RESUME_TOKEN_VERIFIED"
                    and current_token == proof_token
                    and acceptable(current_token, current_token["user_sha256"])):
                startup_record = proof
                startup_status = {"status": "VERIFIED", "root_cause": None, "api": "TWO_STAGE_CREATEPROCESSASUSERW"}
            else:
                startup_record = proof
                startup_status = {"status": "NOT_COVERED", "root_cause": "STARTUP_PROOF_CONTROL_BROKEN"}
        elif diagnostic.get("current_token", {}).get("elevated"):
            startup = out / "startup.json"
            report["commands"].append(execute("startup", ["tools/restricted_startup_v1.py", "--out", str(startup)], out, 180))
            startup_record = json.loads(startup.read_bytes()) if startup.exists() else {}
            startup_status = (
                {"status": "VERIFIED", "root_cause": None, "api": "CreateProcessAsUserW"}
                if startup_record.get("status") == "VERIFIED"
                else {"status": "NOT_COVERED", "root_cause": startup_record.get("reason", "STARTUP_NOT_OBSERVED")}
            )
        else:
            startup_record = {"not_covered": "assessment caller is not elevated; hosted reduction path cannot be exercised"}
            startup_status = {"status": "NOT_COVERED", "root_cause": "ELEVATED_HOSTED_CALLER_UNAVAILABLE"}
        v02_report = json.loads((v02 / "report.json").read_bytes()) if (v02 / "report.json").exists() else {}
        v04_report = json.loads((v04 / "report.json").read_bytes()) if (v04 / "report.json").exists() else {}
        cases = v02_report.get("cases", [])
        scenarios = v04_report.get("scenarios", [])
        control_causes = campaign_control_causes(cases, scenarios)
        if control_causes:
            checks = {
                "appcontainer_identity": "NOT_COVERED",
                "named_pipe_authentication": "NOT_COVERED",
                "broker_permissions": "NOT_COVERED",
                "file_access_bypass": "NOT_COVERED",
                "execution_and_crash_recovery": "NOT_COVERED",
                "restricted_token_child_startup": startup_status["status"],
            }
            report["campaign_precondition"] = "CONTROL_BROKEN"
            report["control_broken_causes"] = control_causes
        else:
            checks = {
                "appcontainer_identity": "VERIFIED" if all((named(cases, key) or {}).get("passed") for key in ("caller_identity", "broker_os_scope")) else "REFUTED",
                "named_pipe_authentication": "VERIFIED" if all((named(cases, key) or {}).get("passed") for key in ("unauthorized_pipe_client", "caller_identity", "server_identity")) else "REFUTED",
                "broker_permissions": "VERIFIED" if (named(cases, "broker_os_scope") or {}).get("passed") else "REFUTED",
                "file_access_bypass": "VERIFIED" if (named(cases, "agent_os_bypass") or {}).get("passed") and (named(cases, "agent_os_bypass") or {}).get("operations") == 9 else "REFUTED",
                "execution_and_crash_recovery": "VERIFIED" if v04_report.get("passed") and len(scenarios) == 15 else "REFUTED",
                "restricted_token_child_startup": startup_status["status"],
            }
        core = all(value == "VERIFIED" for key, value in checks.items() if key != "restricted_token_child_startup")
        report.update(status="VERIFIED" if core and checks["restricted_token_child_startup"] == "VERIFIED" else "PARTIAL" if core else "HOLD",
                      checks=checks, startup_classification=startup_status, startup_observation=startup_record,
                      v02_case_count=len(cases), v04_scenario_count=len(scenarios),
                      limited_child_requirement="REQUIRED_FOR_WINDOWS_GATE", hosted_runner="NOT_AN_INDEPENDENT_SECOND_MACHINE")
    (out / "report.json").write_bytes(json.dumps(report, sort_keys=True, indent=2).encode("ascii") + b"\n")
    print(json.dumps(report, sort_keys=True))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--startup-proof", type=Path); args = parser.parse_args(argv)
    run.startup_proof = args.startup_proof
    result = run(args.out)
    return 0 if result["status"] in {"VERIFIED", "PARTIAL", "NOT_COVERED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

