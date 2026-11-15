"""Integrity v8 for PR8 CI routing. Preserves v4/v5/v6/v7 history.

The fixed v7 Git commit is the predecessor trust anchor; the workflow's
independently reviewed policy + verifier pins bootstrap this verifier. The
workflow is hashed after normalizing ONLY those two pin values, avoiding a
circular hash dependency. This is source integrity, not production authority.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREDECESSOR = "b754be15fa16e30017efc92140e7d6879139b6a5"
WORKFLOW = ".github/workflows/resonance-guardian-v1.yml"
OLD_CONTROLS = {
    "integrity/v7/policy.json",
    "integrity/v7/frozen.sha256.json",
    "tools/integrity_v7.py",
}
NEW_CONTROLS = {"integrity/v8/policy.json", "tools/integrity_v8.py"}
IGNORED_DIRS = {".git", "__pycache__", "build", ".pytest_cache", ".venv", "venv"}
PIN_KEYS = ("INTEGRITY_V8_POLICY_SHA256", "INTEGRITY_V8_VERIFIER_SHA256")
POLICY_FIELDS = {
    "schema", "predecessor", "historical_inventory", "historical_inventory_sha256",
    "historical_controls", "historical_workflow_sha256",
    "workflow", "workflow_template_sha256", "replacement_paths",
    "new_controls", "frozen_count",
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def require(cond, reason):
    if not cond:
        raise ValueError(reason)


def load(path):
    raw = path.read_bytes()

    def pairs(items):
        out = {}
        for k, value in items:
            require(k not in out, "DUPLICATE_MEMBER")
            out[k] = value
        return out

    obj = json.loads(raw, object_pairs_hook=pairs)
    require(canonical(obj) == raw, "NONCANONICAL")
    return obj, raw


def historical(path):
    return subprocess.check_output(["git", "show", PREDECESSOR + ":" + path], cwd=ROOT)


def normalize_workflow(raw):
    content = raw.decode("utf-8")
    embedded = {}
    for key in PIN_KEYS:
        pattern = r"(?m)^(  " + re.escape(key) + r": )([0-9a-f]{64})$"
        matches = list(re.finditer(pattern, content))
        require(len(matches) == 1, "WORKFLOW_PIN_SHAPE_" + key)
        embedded[key] = matches[0].group(2)
        content = re.sub(pattern, lambda m: m.group(1) + "0" * 64, content, count=1)
    return content.encode("utf-8"), embedded


def inventory():
    result = {}
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in IGNORED_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.name.endswith(".pyc"):
            continue
        result[path.relative_to(ROOT).as_posix()] = digest(path.read_bytes())
    return result


def verify(expected_policy_pin):
    require(re.fullmatch(r"[0-9a-f]{64}", expected_policy_pin) is not None, "POLICY_PIN_FORMAT")
    policy, raw_policy = load(ROOT / "integrity/v8/policy.json")
    require(digest(raw_policy) == expected_policy_pin, "POLICY_PIN")
    require(type(policy) is dict and set(policy) == POLICY_FIELDS, "POLICY_SCHEMA")
    require(policy["schema"] == "guardian.integrity-transition.v8" and policy["predecessor"] == PREDECESSOR, "POLICY_ID")
    require(policy["historical_inventory"] == "integrity/v7/frozen.sha256.json", "HISTORICAL_INVENTORY_PATH")
    require(policy["workflow"] == WORKFLOW and policy["replacement_paths"] == [WORKFLOW], "WORKFLOW_SCOPE")
    require(set(policy["historical_controls"]) == OLD_CONTROLS and
            set(policy["new_controls"]) == NEW_CONTROLS and
            len(policy["new_controls"]) == len(NEW_CONTROLS), "CONTROL_SCOPE")
    require(subprocess.run(["git", "merge-base", "--is-ancestor", PREDECESSOR, "HEAD"],
                           cwd=ROOT, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL).returncode == 0, "ANCESTRY")

    historic_manifest = ROOT / policy["historical_inventory"]
    require(digest(historic_manifest.read_bytes()) == policy["historical_inventory_sha256"], "INHERITED_MANIFEST_SHA")
    require(digest(historical(policy["historical_inventory"])) == policy["historical_inventory_sha256"], "HISTORICAL_MANIFEST_COMMIT")
    manifest, _ = load(historic_manifest)
    require(manifest["schema"] == "guardian.integrity-frozen-inventory.v7" and
            manifest["base_commit"] == "be31c67bf5a5dac41260d17fb7aabc01d7539e66", "INHERITED_INVENTORY_ID")
    expected = manifest["files"]
    require(type(expected) is dict and len(expected) == policy["frozen_count"] == 381, "INHERITED_COUNT")
    require(expected[WORKFLOW] == policy["historical_workflow_sha256"] == digest(historical(WORKFLOW)),
            "HISTORICAL_WORKFLOW")
    for name, expected_sha in policy["historical_controls"].items():
        require(name in OLD_CONTROLS and expected_sha == digest(historical(name)), "HISTORICAL_CONTROL_ID_" + name)
        require(digest((ROOT / name).read_bytes()) == expected_sha, "HISTORICAL_CONTROL_CHANGED_" + name)

    workflow_raw = (ROOT / WORKFLOW).read_bytes()
    normalized_workflow, pins = normalize_workflow(workflow_raw)
    require(digest(normalized_workflow) == policy["workflow_template_sha256"], "WORKFLOW_TEMPLATE")
    require(pins["INTEGRITY_V8_POLICY_SHA256"] == expected_policy_pin, "WORKFLOW_POLICY_PIN")
    require(pins["INTEGRITY_V8_VERIFIER_SHA256"] == digest((ROOT / "tools/integrity_v8.py").read_bytes()),
            "WORKFLOW_VERIFIER_PIN")

    actual = inventory()
    allowed = set(expected) | OLD_CONTROLS | NEW_CONTROLS
    missing = sorted(allowed - set(actual))
    extra = sorted(set(actual) - allowed)
    changed = sorted(name for name, sha in expected.items()
                     if name in actual and name != WORKFLOW and actual[name] != sha)
    result = {
        "schema": "guardian.integrity-result.v8",
        "predecessor": PREDECESSOR,
        "passed": not (missing or extra or changed),
        "protected_files": len(allowed),
        "inherited_frozen": len(expected),
        "missing": missing,
        "extra": extra,
        "changed": changed,
        "workflow_transition": "EXPLICIT_NORMALIZED_PINNED",
        "old_integrity_files": "BYTE_PRESERVED",
        "production_ready": False,
    }
    return result


def run_command(repo, pin):
    command = [sys.executable, "-B", str(repo / "tools/integrity_v8.py"),
               "--policy-sha256", pin]
    proc = subprocess.run(command, cwd=repo, capture_output=True, text=True, timeout=30)
    try:
        result = json.loads(proc.stdout)
    except ValueError:
        return {"exit": proc.returncode, "passed": False, "error": "INVALID_OUTPUT", "stderr": proc.stderr[-400:]}
    return {"exit": proc.returncode, "passed": result.get("passed"), "error": result.get("error"),
            "missing": result.get("missing"), "extra": result.get("extra"),
            "changed": result.get("changed")}


def self_test(pin):
    """Disposable physical source/file witnesses, never modify the candidate tree."""
    import shutil
    cases = [
        ("protected_source", "research/guardian_mutual_ipc_v1/verify_evidence.py", "append"),
        ("workflow_body", WORKFLOW, "append"),
        ("historical_policy", "integrity/v7/policy.json", "append"),
        ("v8_policy", "integrity/v8/policy.json", "append"),
        ("v8_verifier", "tools/integrity_v8.py", "append"),
        ("missing_protected", "research/guardian_mutual_ipc_v1/verify_evidence.py", "delete"),
        ("unauthorized_file", "research/guardian_mutual_ipc_v1/UNAUTHORIZED.txt", "new"),
    ]
    rows = []
    with tempfile.TemporaryDirectory(prefix="guardian-ci-v8-") as tmpdir:
        repo = Path(tmpdir) / "clone"
        subprocess.run(["git", "clone", "--quiet", "--no-local", str(ROOT), str(repo)],
                       check=True, capture_output=True, timeout=90)
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        subprocess.run(["git", "checkout", "--quiet", "--detach", sha],
                       check=True, cwd=repo, capture_output=True, timeout=30)
        healthy = run_command(repo, pin)
        require(healthy["exit"] == 0 and healthy["passed"] is True, "SELFTEST_BASELINE")
        for label, relative, action in cases:
            target = repo / relative
            original = target.read_bytes() if target.exists() else None
            try:
                if action == "append":
                    target.write_bytes(original + b"\n# NEGATIVE_WITNESS\n")
                elif action == "delete":
                    target.unlink()
                else:
                    target.write_text("UNAUTHORIZED\n", encoding="ascii")
                negative = run_command(repo, pin)
                require(negative["exit"] != 0 and negative["passed"] is not True, "MUTANT_SURVIVED_" + label)
                classification = "KILLED"
            finally:
                if original is None:
                    target.unlink(missing_ok=True)
                else:
                    target.write_bytes(original)
            restored = run_command(repo, pin)
            require(restored["exit"] == 0 and restored["passed"] is True, "SELFTEST_RESTORATION_" + label)
            rows.append({"name": label, "classification": classification,
                         "negative": negative, "restored": True})
    return {"passed": True, "tested": len(rows), "mutations": rows,
            "note": "Physical modifications were confined to a disposable Git clone."}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--policy-sha256", required=True)
    p.add_argument("--out", type=Path)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    try:
        result = verify(args.policy_sha256)
        if not result["passed"]:
            code = 1
        elif args.self_test:
            result = self_test(args.policy_sha256)
            code = 0
        else:
            code = 0
    except Exception as e:
        result = {"passed": False, "error": str(e), "production_ready": False}
        code = 1
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(raw, encoding="utf-8")
    print(raw, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
