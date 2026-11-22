"""Pinned source-integrity transition for the consolidated Guardian RC3 research tree.

This is a versioned, review-bootstrapped source inventory, NOT production authority.
Historical V1 and V8 policies remain untouched and are independently replayed
at their exact frozen commits by the RC3 CI workflow.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/security-repair-v1.yml"
POLICY = "integrity/rc3/policy.json"
MANIFEST = "integrity/rc3/source_sha256.json"
VERIFIER = "tools/integrity_rc3.py"
CONTROLS = {WORKFLOW, POLICY, MANIFEST, VERIFIER}
HISTORY = {
    "pr4_integrity_v1": "e772eebd3ae3fee91237fa62b2caa3be0517684f",
    "pr8_integrity_v8": "299487d7d7884b2cb2adc7df86b6485ee18daba7",
    "pr10_merged": "ab48210542487ec5bc2025f89cf528a71e37201c",
    "pr11_merged": "03f4585c5e79eae62db656941bfd823be4782d9f",
    "pr12_merged": "9dceefefd19e264f0248c14cf72be10565a90e43",
}
PIN_KEYS = ("RC3_POLICY_SHA256", "RC3_VERIFIER_SHA256")
SKIP_PARTS = {".git", "build", "__pycache__", ".pytest_cache", ".venv", "venv"}
TEXT_EXTS = {
    ".py", ".json", ".md", ".txt", ".rst", ".yaml", ".yml", ".toml",
    ".in", ".ini", ".sh", ".c", ".h", ".gitignore", ".gitattributes",
}
HEX64 = re.compile(r"[a-f0-9]{64}\Z")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":")).encode("ascii") + b"\n"


def strict_load(data):
    def pairs(values):
        obj = {}
        for name, value in values:
            require(name not in obj, "DUPLICATE_MEMBER")
            obj[name] = value
        return obj
    value = json.loads(data, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("NONFINITE")))
    require(canonical(value) == data, "NONCANONICAL_JSON")
    return value


def safe_name(name):
    require(isinstance(name, str) and name and "\\" not in name, "UNSAFE_NAME")
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts
            and path.as_posix() == name and name not in (".", ".."), "UNSAFE_PATH")
    return name


def source_bytes(path):
    data = path.read_bytes()
    if path.suffix.lower() in TEXT_EXTS or path.name in (
            ".gitignore", ".gitattributes", "Dockerfile", "LICENSE"):
        return data.replace(b"\r\n", b"\n")
    return data


def inventory():
    raw = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT)
    names = sorted(set(raw.decode("utf-8").split("\0")) - {""})
    items = {}
    for name in names:
        safe_name(name)
        if any(part in SKIP_PARTS for part in PurePosixPath(name).parts):
            continue
        path = ROOT / name
        require(not path.is_symlink(), "SYMLINK_UNTRUSTED:" + name)
        if path.is_file():
            items[name] = digest(source_bytes(path))
    return items


def normalized_workflow(raw):
    content = raw.decode("utf-8").replace("\r\n", "\n")
    embedded = {}
    for key in PIN_KEYS:
        pattern = r"(?m)^(  " + re.escape(key) + r": )([a-f0-9]{64})$"
        found = list(re.finditer(pattern, content))
        require(len(found) == 1, "WORKFLOW_PIN_SHAPE_" + key)
        embedded[key] = found[0].group(2)
        content = re.sub(pattern, lambda m: m.group(1) + ("0" * 64),
                         content, count=1)
    return content.encode("utf-8"), embedded


def verify(policy_pin, verifier_pin):
    require(bool(HEX64.fullmatch(policy_pin)), "POLICY_PIN_FORMAT")
    require(bool(HEX64.fullmatch(verifier_pin)), "VERIFIER_PIN_FORMAT")
    require(digest((ROOT / VERIFIER).read_bytes()) == verifier_pin, "VERIFIER_PIN")
    raw_policy = (ROOT / POLICY).read_bytes()
    require(digest(raw_policy) == policy_pin, "POLICY_PIN")
    policy = strict_load(raw_policy)
    require(isinstance(policy, dict) and set(policy) == {
        "schema", "history", "manifest", "manifest_sha256",
        "workflow", "workflow_template_sha256", "protected_count",
        "production_ready"}, "POLICY_FIELDS")
    require(policy["schema"] == "guardian.rc3.integrity-transition.v1"
            and policy["production_ready"] is False, "POLICY_ID")
    require(policy["history"] == HISTORY, "HISTORY_PINS")
    for name, commit in HISTORY.items():
        result = subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"],
                                cwd=ROOT, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        require(result.returncode == 0, "HISTORY_NOT_ANCESTOR_" + name)
    require(policy["manifest"] == MANIFEST and policy["workflow"] == WORKFLOW,
            "CONTROL_PATH")
    raw_manifest = (ROOT / MANIFEST).read_bytes()
    require(digest(raw_manifest) == policy["manifest_sha256"], "MANIFEST_PIN")
    expected = strict_load(raw_manifest)
    require(isinstance(expected, dict) and len(expected) == policy["protected_count"],
            "MANIFEST_COUNT")
    for name, value in expected.items():
        safe_name(name)
        require(name not in CONTROLS and isinstance(value, str)
                and HEX64.fullmatch(value), "MANIFEST_ENTRY")
    wf, embedded = normalized_workflow((ROOT / WORKFLOW).read_bytes())
    require(digest(wf) == policy["workflow_template_sha256"], "WORKFLOW_TEMPLATE")
    require(embedded["RC3_POLICY_SHA256"] == policy_pin and
            embedded["RC3_VERIFIER_SHA256"] == verifier_pin, "WORKFLOW_PINS")
    actual = inventory()
    permitted = set(expected) | CONTROLS
    missing = sorted(permitted - set(actual))
    extra = sorted(set(actual) - permitted)
    changed = sorted(name for name in expected
                     if name in actual and actual[name] != expected[name])
    verdict = not (missing or extra or changed)
    return {
        "schema": "guardian.rc3.integrity-result.v1",
        "passed": verdict,
        "production_ready": False,
        "historical_commits_confirmed": len(HISTORY),
        "protected_files": len(expected),
        "missing": missing,
        "extra": extra,
        "changed": changed,
        "bootstrap": "EXPLICIT_WORKFLOW_POLICY_AND_VERIFIER_PINS",
        "historical_policies": "NOT_REWRITTEN",
    }


def run_check(path, pin, verifier_pin):
    proc = subprocess.run([sys.executable, "-B", str(path / VERIFIER),
                           "--policy-sha256", pin,
                           "--verifier-sha256", verifier_pin],
                          cwd=path, capture_output=True, text=True, timeout=40)
    try:
        result = json.loads(proc.stdout)
        return proc.returncode, bool(result.get("passed"))
    except ValueError:
        return proc.returncode, False


def self_test(pin, verifier_pin):
    """Physical mutation controls inside disposable Git worktree at exact HEAD."""
    import shutil
    cases = [
        ("candidate_code_tamper", "research/scoped_execution_lab_v3/lab.py", "append"),
        ("original_core_tamper", "research/resonance_core_v23/core_v2_3.py", "append"),
        ("historical_guardian_tamper", "research/guardian_mutual_ipc_v1/verify_evidence.py", "append"),
        ("missing_candidate", "research/scoped_execution_lab_v3/lab.py", "delete"),
        ("manifest_tamper", MANIFEST, "append"),
        ("policy_tamper", POLICY, "append"),
        ("verifier_tamper", VERIFIER, "append"),
        ("workflow_tamper", WORKFLOW, "append"),
        ("unexpected_file", "RC3_UNAUTHORIZED_NEW_FILE.tmp", "new"),
    ]
    cases_result = []
    with tempfile.TemporaryDirectory(prefix="guardian-rc3-integrity-") as temp:
        worktree = Path(temp) / "worktree"
        subprocess.run(["git", "worktree", "add", "--detach", str(worktree), "HEAD"],
                       cwd=ROOT, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, timeout=120)
        try:
            healthy = run_check(worktree, pin, verifier_pin)
            require(healthy == (0, True), "SELFTEST_BASELINE")
            for label, relative, action in cases:
                target = worktree / relative
                old = target.read_bytes() if target.is_file() else None
                require(old is not None or action == "new", "MUTANT_TARGET_MISSING")
                try:
                    if action == "append":
                        target.write_bytes(old + b"\nMUTATION_TEST\n")
                    elif action == "delete":
                        target.unlink()
                    else:
                        target.write_bytes(b"unauthorized\n")
                    negative = run_check(worktree, pin, verifier_pin)
                    require(negative[0] != 0 and negative[1] is False,
                            "MUTANT_SURVIVED_" + label)
                finally:
                    if old is not None:
                        target.write_bytes(old)
                    else:
                        target.unlink(missing_ok=True)
                restored = run_check(worktree, pin, verifier_pin)
                require(restored == (0, True), "MUTANT_RESTORE_" + label)
                cases_result.append({"name": label, "status": "KILLED",
                                     "restored": True})
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(worktree)],
                           cwd=ROOT, check=False, capture_output=True, timeout=60)
    return {"passed": True, "mutations": cases_result,
            "killed": len(cases_result), "survived": 0,
            "production_ready": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        result = verify(args.policy_sha256, args.verifier_sha256)
        code = 0 if result["passed"] else 1
        if code == 0 and args.self_test:
            result = self_test(args.policy_sha256, args.verifier_sha256)
    except Exception as e:
        result = {"passed": False, "error": type(e).__name__ + ":" + str(e),
                  "production_ready": False}
        code = 1
    raw = canonical(result)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(raw)
    print(raw.decode(), end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
