"""Signed execution receipts and a read-only independent verification path."""

import base64
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from research.auth_gateway_v1.canonical import canonical_json_bytes, public_fingerprint
from research.auth_gateway_v1.errors import SecurityError
from research.auth_gateway_v1.model import RequestBinding
from research.auth_gateway_v1.grant import public_key_bytes

from .scoped_grant import verify_scoped_execution_grant


RECEIPT_FIELDS = frozenset({"payload", "signature", "public_key_fingerprint"})
PAYLOAD_FIELDS = frozenset(
    {
        "schema",
        "receipt_id",
        "recorded_at",
        "classification",
        "lifecycle",
        "principal",
        "request_id",
        "request_sha256",
        "grant_id",
        "grant_sha256",
        "grant_signature_sha256",
        "grant_key_fingerprint",
        "worker_sha256",
        "image_identity",
        "admission_scope",
        "trust_version",
        "container_started",
        "exit_code",
        "timed_out",
        "launch_error",
        "outcome_sha256",
        "stdout_sha256",
        "stderr_sha256",
        "evidence_sha256",
    }
)
PRINCIPAL_FIELDS = frozenset({"subject", "role", "wallet"})
LIFECYCLE_CLASSIFICATIONS = {
    "COMMITTED": "EXECUTED",
    "ABORTED": "AUTHORIZED",
    "RECOVERY_REQUIRED": "RECOVERY_REQUIRED",
}
HEX = re.compile(r"[0-9a-f]{64}\Z")
FINGERPRINT = re.compile(r"[0-9a-f]{24}\Z")


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _hex_text(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def issue_execution_receipt(
    private_key,
    claim,
    grant,
    grant_sha256,
    grant_payload,
    lifecycle,
    recorded_at,
    container_started,
    outcome,
    outcome_sha256,
):
    if lifecycle not in LIFECYCLE_CLASSIFICATIONS:
        raise SecurityError("RECEIPT_LIFECYCLE")
    if type(claim) is not dict or claim.get("state") != "PREPARED":
        raise SecurityError("RECEIPT_ADMISSION")
    principal = {
        "subject": grant_payload["subject"],
        "role": grant_payload["role"],
        "wallet": grant_payload["wallet"],
    }
    observed = {
        "container_started": container_started,
        "exit_code": outcome["exit_code"],
        "timed_out": outcome["timed_out"],
        "launch_error": outcome["launch_error"],
        "outcome_sha256": outcome_sha256,
        "stdout_sha256": outcome["stdout_sha256"],
        "stderr_sha256": outcome["stderr_sha256"],
    }
    payload = {
        "schema": "guardian.execution-receipt.v1",
        "receipt_id": claim["attempt_id"],
        "recorded_at": recorded_at,
        "classification": LIFECYCLE_CLASSIFICATIONS[lifecycle],
        "lifecycle": lifecycle,
        "principal": principal,
        "request_id": grant_payload["binding"]["request_id"],
        "request_sha256": grant_payload["binding_sha256"],
        "grant_id": grant_payload["grant_id"],
        "grant_sha256": grant_sha256,
        "grant_signature_sha256": _sha(base64.b64decode(grant["signature"], validate=True)),
        "grant_key_fingerprint": grant_payload["grant_key_fingerprint"],
        "worker_sha256": grant_payload["worker_sha256"],
        "image_identity": grant_payload["image_identity"],
        "admission_scope": grant_payload["admission_scope"],
        "trust_version": grant_payload["trust_version"],
        **observed,
    }
    payload["evidence_sha256"] = _sha(canonical_json_bytes(observed))
    encoded = canonical_json_bytes(payload)
    signature = private_key.sign(encoded)
    fingerprint = public_fingerprint(public_key_bytes(private_key))
    return {
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key_fingerprint": fingerprint,
    }


def verify_execution_evidence(
    request,
    grant,
    receipt,
    grant_public_key,
    receipt_public_key,
    expected_scope,
    expected_worker_sha256,
    expected_image_identity,
    expected_trust_version,
):
    """Verify only supplied artifacts; never reads or changes durable state."""
    if receipt is None:
        return {"classification": "UNVERIFIABLE", "verified": False, "reason": "RECEIPT_MISSING"}
    try:
        if type(receipt) is not dict or set(receipt) != RECEIPT_FIELDS:
            raise SecurityError("RECEIPT_SHAPE")
        payload = receipt.get("payload")
        if type(payload) is not dict or set(payload) != PAYLOAD_FIELDS:
            raise SecurityError("RECEIPT_PAYLOAD")
        if payload["schema"] != "guardian.execution-receipt.v1":
            raise SecurityError("RECEIPT_VERSION")
        if payload["lifecycle"] not in LIFECYCLE_CLASSIFICATIONS:
            raise SecurityError("RECEIPT_LIFECYCLE")
        if payload["classification"] != LIFECYCLE_CLASSIFICATIONS[payload["lifecycle"]]:
            raise SecurityError("RECEIPT_CLASSIFICATION")
        if type(payload["principal"]) is not dict or set(payload["principal"]) != PRINCIPAL_FIELDS:
            raise SecurityError("RECEIPT_PRINCIPAL")
        receipt_public = receipt_public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if receipt["public_key_fingerprint"] != public_fingerprint(receipt_public):
            raise SecurityError("RECEIPT_KEY_BINDING")
        try:
            signature = base64.b64decode(receipt["signature"], validate=True)
            receipt_public_key.verify(signature, canonical_json_bytes(payload))
        except (ValueError, TypeError, InvalidSignature) as error:
            raise SecurityError("RECEIPT_SIGNATURE") from error
        if type(payload["recorded_at"]) is not int:
            raise SecurityError("RECEIPT_TIME")
        if (
            type(payload["receipt_id"]) is not str
            or not payload["receipt_id"]
            or type(payload["request_id"]) is not str
            or not payload["request_id"]
            or type(payload["grant_id"]) is not str
            or not payload["grant_id"]
            or type(payload["container_started"]) is not bool
            or type(payload["timed_out"]) is not bool
            or (payload["exit_code"] is not None and type(payload["exit_code"]) is not int)
            or (payload["launch_error"] is not None and type(payload["launch_error"]) is not str)
        ):
            raise SecurityError("RECEIPT_FIELD_TYPE")
        for name in (
            "request_sha256",
            "grant_sha256",
            "grant_signature_sha256",
            "worker_sha256",
            "outcome_sha256",
            "stdout_sha256",
            "stderr_sha256",
            "evidence_sha256",
        ):
            if not _hex_text(payload[name]):
                raise SecurityError("RECEIPT_DIGEST")
        if type(payload["grant_key_fingerprint"]) is not str or FINGERPRINT.fullmatch(payload["grant_key_fingerprint"]) is None:
            raise SecurityError("RECEIPT_DIGEST")
        binding = RequestBinding.from_request(request)
        grant_payload, grant_sha256 = verify_scoped_execution_grant(
            grant,
            grant_public_key,
            payload["recorded_at"],
            expected_scope,
            binding,
            expected_worker_sha256,
            expected_image_identity,
            expected_trust_version,
        )
        expected_principal = {
            "subject": grant_payload["subject"],
            "role": grant_payload["role"],
            "wallet": grant_payload["wallet"],
        }
        grant_signature_sha256 = _sha(base64.b64decode(grant["signature"], validate=True))
        bindings = (
            payload["principal"] == expected_principal,
            payload["request_id"] == binding.request_id,
            payload["request_sha256"] == binding.digest(),
            payload["grant_id"] == grant_payload["grant_id"],
            payload["grant_sha256"] == grant_sha256,
            payload["grant_signature_sha256"] == grant_signature_sha256,
            payload["grant_key_fingerprint"] == grant_payload["grant_key_fingerprint"],
            payload["worker_sha256"] == expected_worker_sha256,
            payload["image_identity"] == expected_image_identity,
            payload["admission_scope"] == expected_scope,
            payload["trust_version"] == expected_trust_version,
        )
        if not all(bindings):
            raise SecurityError("RECEIPT_BINDING")
        observed = {
            "container_started": payload["container_started"],
            "exit_code": payload["exit_code"],
            "timed_out": payload["timed_out"],
            "launch_error": payload["launch_error"],
            "outcome_sha256": payload["outcome_sha256"],
            "stdout_sha256": payload["stdout_sha256"],
            "stderr_sha256": payload["stderr_sha256"],
        }
        if payload["evidence_sha256"] != _sha(canonical_json_bytes(observed)):
            raise SecurityError("RECEIPT_EVIDENCE")
        if payload["lifecycle"] == "COMMITTED" and (
            payload["container_started"] is not True
            or payload["timed_out"] is not False
            or payload["launch_error"] is not None
            or type(payload["exit_code"]) is not int
        ):
            raise SecurityError("RECEIPT_EXECUTION_CONTRADICTION")
        if payload["lifecycle"] == "ABORTED" and (
            payload["container_started"] is not False
            or payload["timed_out"] is not False
            or type(payload["launch_error"]) is not str
            or payload["exit_code"] is not None
        ):
            raise SecurityError("RECEIPT_ABORT_CONTRADICTION")
        return {
            "classification": payload["classification"],
            "verified": True,
            "receipt_id": payload["receipt_id"],
            "grant_id": payload["grant_id"],
            "request_sha256": payload["request_sha256"],
            "evidence_sha256": payload["evidence_sha256"],
        }
    except (SecurityError, KeyError, TypeError, ValueError) as error:
        reason = error.code if isinstance(error, SecurityError) else "RECEIPT_INPUT"
        return {"classification": "REFUTED", "verified": False, "reason": reason}
