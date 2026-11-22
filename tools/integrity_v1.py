"""Layered integrity verification with an independently supplied policy pin.

The legacy manifest is immutable. PR #2/#3 additions are frozen in a second
manifest. Repair files and explicit replacements are held in a third layer.
The caller must supply the expected SHA-256 of policy.json; the exact Git commit
or CI workflow is the bootstrap trust root, because a checkout cannot
cryptographically authenticate all of its own verifier bytes.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
HEX = re.compile(r"[0-9a-f]{64}\Z")
GIT_COMMIT_HEX = re.compile(r"[0-9a-f]{40}\Z")
POLICY_FIELDS = {"schema", "base_commit", "layers", "repair", "control_files", "bootstrap_trust"}
LAYER_FIELDS = {"name", "manifest", "manifest_sha256", "entries"}
REPAIR_FIELDS = {"manifest", "manifest_sha256", "additions", "replacements"}
REPLACEMENT_FIELDS = {"source_layer", "previous_sha256", "sha256"}


class IntegrityError(ValueError):
    pass


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise IntegrityError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(IntegrityError(f"nonfinite {value}")))
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise IntegrityError(f"invalid JSON: {exc}") from exc


def safe_name(name):
    if type(name) is not str or not name or "\\" in name:
        raise IntegrityError("manifest path must be nonempty POSIX text")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or name != path.as_posix():
        raise IntegrityError(f"unsafe manifest path: {name}")
    return name


def load_map(path, expected_sha=None, expected_entries=None):
    raw = path.read_bytes()
    if type(expected_sha) is not str or not HEX.fullmatch(expected_sha):
        raise IntegrityError("invalid pinned manifest digest")
    if type(expected_entries) is not int or expected_entries < 0:
        raise IntegrityError("invalid pinned manifest entry count")
    if expected_sha is not None and sha(raw) != expected_sha:
        raise IntegrityError(f"tampered manifest: {path.relative_to(ROOT).as_posix()}")
    value = strict_json(raw)
    if type(value) is not dict:
        raise IntegrityError("manifest must be an object")
    result = {}
    for name, digest in value.items():
        safe_name(name)
        if type(digest) is not str or not HEX.fullmatch(digest):
            raise IntegrityError(f"invalid digest for {name}")
        result[name] = digest
    if expected_entries is not None and len(result) != expected_entries:
        raise IntegrityError(f"manifest entry count mismatch: {path}")
    return result


def actual_inventory():
    raw = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT)
    names = sorted(set(raw.decode("utf-8").split("\0")) - {""})
    return {name: sha((ROOT / name).read_bytes()) for name in names if (ROOT / name).is_file()}


def verify(policy_path, expected_policy_sha256):
    policy_path = Path(policy_path).resolve()
    if ROOT not in policy_path.parents:
        raise IntegrityError("policy must be inside repository")
    policy_raw = policy_path.read_bytes()
    if type(expected_policy_sha256) is not str or not HEX.fullmatch(expected_policy_sha256) or sha(policy_raw) != expected_policy_sha256:
        raise IntegrityError("policy SHA-256 does not match independent pin")
    policy = strict_json(policy_raw)
    if type(policy) is not dict or set(policy) != POLICY_FIELDS or policy["schema"] != "guardian.layered-integrity.v1":
        raise IntegrityError("unsupported policy schema")
    if type(policy["base_commit"]) is not str or not GIT_COMMIT_HEX.fullmatch(policy["base_commit"]):
        raise IntegrityError("invalid base commit")
    if subprocess.run(["git", "merge-base", "--is-ancestor", policy["base_commit"], "HEAD"], cwd=ROOT).returncode:
        raise IntegrityError("base commit is not an ancestor")

    if type(policy["layers"]) is not list or not policy["layers"]:
        raise IntegrityError("at least one frozen layer is required")
    if type(policy["control_files"]) is not list or type(policy["bootstrap_trust"]) is not list:
        raise IntegrityError("control and bootstrap paths require lists")

    expected = {}
    layer_maps = {}
    for layer in policy["layers"]:
        if type(layer) is not dict or set(layer) != LAYER_FIELDS:
            raise IntegrityError("invalid layer descriptor")
        name = safe_name(layer["name"]); manifest_name = safe_name(layer["manifest"])
        if name in layer_maps:
            raise IntegrityError(f"duplicate layer name: {name}")
        manifest = load_map(ROOT / manifest_name, layer["manifest_sha256"], layer["entries"])
        overlap = set(expected) & set(manifest)
        if overlap:
            raise IntegrityError(f"overlapping frozen layers: {sorted(overlap)[:3]}")
        expected.update(manifest); layer_maps[name] = manifest

    repair = policy["repair"]
    if type(repair) is not dict or set(repair) != REPAIR_FIELDS:
        raise IntegrityError("invalid repair layer")
    repair_name = safe_name(repair["manifest"])
    if type(repair["manifest_sha256"]) is not str or not HEX.fullmatch(repair["manifest_sha256"]):
        raise IntegrityError("invalid pinned repair manifest digest")
    if type(repair["additions"]) is not int or repair["additions"] < 0 or type(repair["replacements"]) is not int or repair["replacements"] < 0:
        raise IntegrityError("invalid repair manifest counts")
    repair_raw = (ROOT / repair_name).read_bytes()
    if sha(repair_raw) != repair["manifest_sha256"]:
        raise IntegrityError("tampered repair manifest")
    repair_manifest = strict_json(repair_raw)
    if type(repair_manifest) is not dict or set(repair_manifest) != {"schema", "additions", "replacements"} or repair_manifest["schema"] != "guardian.repair-files.v1":
        raise IntegrityError("invalid repair manifest schema")
    if type(repair_manifest["additions"]) is not dict or type(repair_manifest["replacements"]) is not dict:
        raise IntegrityError("repair additions and replacements must be objects")
    if len(repair_manifest["additions"]) != repair["additions"] or len(repair_manifest["replacements"]) != repair["replacements"]:
        raise IntegrityError("repair manifest count mismatch")
    for name, digest in repair_manifest["additions"].items():
        safe_name(name)
        if name in expected or type(digest) is not str or not HEX.fullmatch(digest):
            raise IntegrityError(f"invalid repair addition: {name}")
        expected[name] = digest
    replacements = {}
    for name, row in repair_manifest["replacements"].items():
        safe_name(name)
        if type(row) is not dict or set(row) != REPLACEMENT_FIELDS or type(row["source_layer"]) is not str or row["source_layer"] not in layer_maps:
            raise IntegrityError(f"invalid replacement: {name}")
        if (type(row["previous_sha256"]) is not str or type(row["sha256"]) is not str
                or layer_maps[row["source_layer"]].get(name) != row["previous_sha256"]
                or not HEX.fullmatch(row["sha256"])):
            raise IntegrityError(f"replacement does not preserve prior digest: {name}")
        expected[name] = row["sha256"]; replacements[name] = row

    controls = set()
    for name in policy["control_files"]:
        safe_name(name); controls.add(name)
    required_controls = {policy_path.relative_to(ROOT).as_posix(), *(layer["manifest"] for layer in policy["layers"]), repair["manifest"]}
    if controls != required_controls:
        raise IntegrityError("control file set mismatch")
    bootstrap = set()
    for name in policy["bootstrap_trust"]:
        safe_name(name); bootstrap.add(name)
    if len(controls) != len(policy["control_files"]) or len(bootstrap) != len(policy["bootstrap_trust"]):
        raise IntegrityError("duplicate control or bootstrap path")
    if (set(expected) & controls) or (set(expected) & bootstrap) or (controls & bootstrap):
        raise IntegrityError("inventory, control, and bootstrap sets must be disjoint")
    actual = actual_inventory()
    missing = sorted(set(expected) - set(actual))
    changed = sorted(name for name in set(expected) & set(actual) if expected[name] != actual[name])
    unauthorized = sorted(set(actual) - set(expected) - controls - bootstrap)
    control_missing = sorted(controls - set(actual))
    bootstrap_missing = sorted(bootstrap - set(actual))
    result = {
        "schema": "guardian.layered-integrity-result.v1",
        "policy_sha256": expected_policy_sha256,
        "base_commit": policy["base_commit"],
        "frozen_entries": sum(len(value) for value in layer_maps.values()),
        "repair_additions": len(repair_manifest["additions"]),
        "authorized_replacements": len(replacements),
        "actual_files": len(actual),
        "missing": missing,
        "modified": changed,
        "unexpected_or_unauthorized": unauthorized,
        "control_missing": control_missing,
        "bootstrap_missing": bootstrap_missing,
        "bootstrap_trust": policy["bootstrap_trust"],
    }
    result["passed"] = not any((missing, changed, unauthorized, control_missing, bootstrap_missing))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=ROOT / "integrity/v1/policy.json")
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify(args.policy, args.policy_sha256); code = 0 if result["passed"] else 1
    except (IntegrityError, OSError, UnicodeError, subprocess.CalledProcessError) as exc:
        result = {"schema": "guardian.layered-integrity-result.v1", "passed": False, "error": str(exc)}; code = 2
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True); args.out.write_bytes(raw)
    print(raw.decode("ascii"), end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())

