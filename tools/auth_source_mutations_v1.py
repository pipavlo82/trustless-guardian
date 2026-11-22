"""Physical auth-source mutations with fresh and restored controls."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SPECS = (
    ("jwt-role", "research/auth_gateway_v1/jwt_auth.py", 'if claims["role"] not in ALLOWED_ROLES:', 'if False and claims["role"] not in ALLOWED_ROLES:', "test_jwt_role_not_registered"),
    ("jwt-request-binding", "research/auth_gateway_v1/jwt_auth.py", 'if claims[name] != expected[name]:', 'if False and claims[name] != expected[name]:', "test_jwt_agent_binding"),
    ("jwt-wallet-subject", "research/auth_gateway_v1/jwt_auth.py", 'if wallet.subject != claims["sub"]:', 'if False and wallet.subject != claims["sub"]:', "test_jwt_wallet_subject_mismatch"),
    ("jwt-key-revocation", "research/auth_gateway_v1/trust.py", 'if record.algorithm != algorithm:\n            raise SecurityError("JWT_KEY_ALGORITHM")\n        if record.revoked:', 'if record.algorithm != algorithm:\n            raise SecurityError("JWT_KEY_ALGORITHM")\n        if False and record.revoked:', "test_jwt_revoked_key"),
    ("trust-unavailable", "research/auth_gateway_v1/trust.py", 'if not self.available:', 'if False and not self.available:', "test_trust_root_unavailable"),
    ("trust-staleness", "research/auth_gateway_v1/trust.py", 'if now - self.observed_at > self.max_staleness:', 'if False and now - self.observed_at > self.max_staleness:', "test_trust_root_stale"),
    ("siwe-resource-binding", "research/auth_gateway_v1/siwe_auth.py", 'if resources != expected_resources(binding):', 'if False and resources != expected_resources(binding):', "test_siwe_resource_substitution"),
    ("siwe-wallet-resource", "research/auth_gateway_v1/siwe_auth.py", 'if binding.agent_id not in wallet.agent_ids or binding.resource_id not in wallet.resource_ids:', 'if False and (binding.agent_id not in wallet.agent_ids or binding.resource_id not in wallet.resource_ids):', "test_siwe_wallet_resource_registry_binding"),
    ("mcp-scope", "research/auth_gateway_v1/mcp_auth.py", 'if "mcp:invoke" not in record.scopes or "tool:" + binding.tool not in record.scopes:', 'if False and ("mcp:invoke" not in record.scopes or "tool:" + binding.tool not in record.scopes):', "test_mcp_scope"),
    ("mcp-request-binding", "research/auth_gateway_v1/mcp_auth.py", 'if not exact:', 'if False and not exact:', "test_mcp_tool_substitution"),
    ("authorization-resource-owner", "research/auth_gateway_v1/policy.py", 'if trust.resource_owners.get(binding.resource_id) != jwt_principal.subject:', 'if False and trust.resource_owners.get(binding.resource_id) != jwt_principal.subject:', "test_valid_signatures_do_not_override_registry_owner"),
    ("authorization-role-operation", "research/auth_gateway_v1/policy.py", 'if binding.operation != "RUN_TOOL" or jwt_principal.role != "OWNER":', 'if False and (binding.operation != "RUN_TOOL" or jwt_principal.role != "OWNER"):', "test_valid_signatures_do_not_override_role"),
    ("grant-request-binding", "research/auth_gateway_v1/grant.py", 'if payload.get("binding") != expected_binding.as_dict() or payload.get("binding_sha256") != expected_binding.digest():', 'if False and (payload.get("binding") != expected_binding.as_dict() or payload.get("binding_sha256") != expected_binding.digest()):', "test_payload_mutation_after_authorization_invalidates_grant"),
    ("grant-signature", "research/auth_gateway_v1/grant.py", 'public_key.verify(signature, canonical_json_bytes(payload))', 'signature = bytes(signature)', "test_grant_payload_mutation"),
    ("nonce-replay", "research/auth_gateway_v1/nonce.py", 'if key in self._entries:', 'if False and key in self._entries:', "test_jwt_replay"),
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def invoke(root, test_name, timeout):
    command = [
        sys.executable,
        "-B",
        "-m",
        "unittest",
        "-q",
        "tests_auth_v1.test_auth_gateway_v1.AuthGatewayTests." + test_name,
    ]
    try:
        process = subprocess.run(command, cwd=root, capture_output=True, timeout=timeout)
        return {
            "exit_code": process.returncode,
            "timed_out": False,
            "stdout_sha256": sha(process.stdout),
            "stderr_sha256": sha(process.stderr),
        }
    except subprocess.TimeoutExpired as error:
        return {
            "exit_code": None,
            "timed_out": True,
            "stdout_sha256": sha(error.stdout or b""),
            "stderr_sha256": sha(error.stderr or b""),
        }


def run(out, timeout):
    results = []
    with tempfile.TemporaryDirectory(prefix="guardian-auth-mutations-") as temp:
        root = Path(temp)
        shutil.copytree(ROOT / "research/auth_gateway_v1", root / "research/auth_gateway_v1")
        (root / "research/__init__.py").write_bytes(b"")
        shutil.copytree(ROOT / "tests_auth_v1", root / "tests_auth_v1")
        for name, relative, old, new, test_name in SPECS:
            path = root / relative
            original = path.read_bytes()
            text = original.decode("utf-8")
            baseline = invoke(root, test_name, timeout)
            matches = text.count(old)
            applied = matches == 1
            mutant = text.replace(old, new, 1).encode("utf-8") if applied else original
            path.write_bytes(mutant)
            mutated = invoke(root, test_name, timeout) if applied else None
            path.write_bytes(original)
            restored_bytes = path.read_bytes() == original
            restored = invoke(root, test_name, timeout)
            if baseline["exit_code"] != 0 or restored["exit_code"] != 0 or not restored_bytes:
                status = "CONTROL_BROKEN"
            elif not applied:
                status = "NOT_APPLIED"
            elif mutated["timed_out"] or mutated["exit_code"] not in (0, 1):
                status = "CRASHED"
            elif mutated["exit_code"] == 0:
                status = "SURVIVED"
            else:
                status = "KILLED"
            results.append({
                "mutation": name,
                "path": relative,
                "test": test_name,
                "match_count": matches,
                "applied": applied,
                "status": status,
                "restored": restored_bytes,
                "original_sha256": sha(original),
                "mutant_sha256": sha(mutant),
                "baseline": baseline,
                "mutated": mutated,
                "restored_control": restored,
            })
    statuses = ("KILLED", "SURVIVED", "NOT_APPLIED", "CRASHED", "CONTROL_BROKEN")
    counts = {status: sum(row["status"] == status for row in results) for status in statuses}
    passed = counts == {
        "KILLED": len(results),
        "SURVIVED": 0,
        "NOT_APPLIED": 0,
        "CRASHED": 0,
        "CONTROL_BROKEN": 0,
    }
    report = {
        "schema": "guardian.auth-source-mutations.v1",
        "population": len(results),
        "counts": counts,
        "results": results,
        "verdict": "PASS" if passed else "HOLD",
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(json.dumps(report, sort_keys=True, indent=2).encode("ascii") + b"\n")
    print(json.dumps({"counts": counts, "verdict": report["verdict"]}, sort_keys=True))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args(argv)
    return 0 if run(args.out, args.timeout)["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
