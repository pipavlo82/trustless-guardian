"""Versioned PR #5 inventory plus explicitly authorized PR #6 changes."""

import argparse
import json
from pathlib import Path
import subprocess

from integrity_v2 import (
    COMMIT,
    HEX,
    ROOT,
    IntegrityError,
    actual_inventory,
    load_digest_map,
    safe_name,
    sha,
    strict_json,
)


POLICY_FIELDS = {"schema", "base_commit", "frozen", "authorized", "control_files", "bootstrap_trust"}
FROZEN_FIELDS = {"manifest", "manifest_sha256", "entries"}
AUTHORIZED_FIELDS = {"manifest", "manifest_sha256", "additions", "replacements"}
REPLACEMENT_FIELDS = {"previous_sha256", "sha256"}


def verify(policy_path, expected_policy_sha256):
    policy_path = Path(policy_path).resolve()
    if ROOT not in policy_path.parents:
        raise IntegrityError("policy must be inside repository")
    policy_raw = policy_path.read_bytes()
    if (
        type(expected_policy_sha256) is not str
        or not HEX.fullmatch(expected_policy_sha256)
        or sha(policy_raw) != expected_policy_sha256
    ):
        raise IntegrityError("policy SHA-256 does not match independent pin")
    policy = strict_json(policy_raw)
    if type(policy) is not dict or set(policy) != POLICY_FIELDS:
        raise IntegrityError("invalid policy shape")
    if policy["schema"] != "guardian.layered-integrity.v3":
        raise IntegrityError("unsupported policy schema")
    if type(policy["base_commit"]) is not str or not COMMIT.fullmatch(policy["base_commit"]):
        raise IntegrityError("invalid base commit")
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", policy["base_commit"], "HEAD"],
        cwd=ROOT,
        capture_output=True,
    ).returncode:
        raise IntegrityError("base commit is not an ancestor")

    frozen = policy["frozen"]
    if type(frozen) is not dict or set(frozen) != FROZEN_FIELDS:
        raise IntegrityError("invalid frozen descriptor")
    frozen_name = safe_name(frozen["manifest"])
    expected = load_digest_map(ROOT / frozen_name, frozen["manifest_sha256"], frozen["entries"])

    authorized = policy["authorized"]
    if type(authorized) is not dict or set(authorized) != AUTHORIZED_FIELDS:
        raise IntegrityError("invalid authorized descriptor")
    authorized_name = safe_name(authorized["manifest"])
    authorized_raw = (ROOT / authorized_name).read_bytes()
    if (
        type(authorized["manifest_sha256"]) is not str
        or not HEX.fullmatch(authorized["manifest_sha256"])
        or sha(authorized_raw) != authorized["manifest_sha256"]
    ):
        raise IntegrityError("authorized manifest digest mismatch")
    manifest = strict_json(authorized_raw)
    if (
        type(manifest) is not dict
        or set(manifest) != {"schema", "additions", "replacements"}
        or manifest["schema"] != "guardian.authorized-additions.v3"
        or type(manifest["additions"]) is not dict
        or type(manifest["replacements"]) is not dict
    ):
        raise IntegrityError("invalid authorized manifest")
    if (
        len(manifest["additions"]) != authorized["additions"]
        or len(manifest["replacements"]) != authorized["replacements"]
    ):
        raise IntegrityError("authorized manifest count mismatch")
    for name, digest in manifest["additions"].items():
        safe_name(name)
        if name in expected or type(digest) is not str or not HEX.fullmatch(digest):
            raise IntegrityError("invalid authorized addition: " + name)
        expected[name] = digest
    replacements = {}
    for name, record in manifest["replacements"].items():
        safe_name(name)
        if type(record) is not dict or set(record) != REPLACEMENT_FIELDS:
            raise IntegrityError("invalid replacement: " + name)
        if (
            expected.get(name) != record["previous_sha256"]
            or type(record["sha256"]) is not str
            or not HEX.fullmatch(record["sha256"])
        ):
            raise IntegrityError("replacement does not preserve historical digest: " + name)
        expected[name] = record["sha256"]
        replacements[name] = record

    controls = {safe_name(name) for name in policy["control_files"]}
    bootstrap = {safe_name(name) for name in policy["bootstrap_trust"]}
    required_controls = {
        policy_path.relative_to(ROOT).as_posix(),
        frozen_name,
        authorized_name,
    }
    if controls != required_controls or len(controls) != len(policy["control_files"]):
        raise IntegrityError("control file set mismatch")
    if len(bootstrap) != len(policy["bootstrap_trust"]):
        raise IntegrityError("duplicate bootstrap path")
    if set(expected) & controls or set(expected) & bootstrap or controls & bootstrap:
        raise IntegrityError("inventory, controls, and bootstrap must be disjoint")

    actual = actual_inventory()
    missing = sorted(set(expected) - set(actual))
    modified = sorted(name for name in set(expected) & set(actual) if expected[name] != actual[name])
    unauthorized_files = sorted(set(actual) - set(expected) - controls - bootstrap)
    control_missing = sorted(controls - set(actual))
    bootstrap_missing = sorted(bootstrap - set(actual))
    result = {
        "schema": "guardian.layered-integrity-result.v3",
        "base_commit": policy["base_commit"],
        "policy_sha256": expected_policy_sha256,
        "frozen_entries": frozen["entries"],
        "authorized_additions": len(manifest["additions"]),
        "authorized_replacements": len(replacements),
        "actual_files": len(actual),
        "missing": missing,
        "modified": modified,
        "unexpected_or_unauthorized": unauthorized_files,
        "control_missing": control_missing,
        "bootstrap_missing": bootstrap_missing,
        "bootstrap_trust": sorted(bootstrap),
    }
    result["passed"] = not any((missing, modified, unauthorized_files, control_missing, bootstrap_missing))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=ROOT / "integrity/v3/policy.json")
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify(args.policy, args.policy_sha256)
        code = 0 if result["passed"] else 1
    except (IntegrityError, OSError, UnicodeError, subprocess.CalledProcessError) as error:
        result = {"schema": "guardian.layered-integrity-result.v3", "passed": False, "error": str(error)}
        code = 2
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(raw)
    print(raw.decode("ascii"), end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
