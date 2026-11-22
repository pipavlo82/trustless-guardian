"""Admission-scope-bound Ed25519 execution grant v2."""

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from research.auth_gateway_v1.canonical import canonical_json_bytes, public_fingerprint
from research.auth_gateway_v1.errors import SecurityError
from research.auth_gateway_v1.grant import public_key_bytes


GRANT_FIELDS = frozenset({"payload", "signature", "public_key_fingerprint"})
PAYLOAD_FIELDS = frozenset(
    {
        "schema",
        "grant_id",
        "not_before",
        "expires_at",
        "subject",
        "role",
        "wallet",
        "binding",
        "binding_sha256",
        "trust_version",
        "admission_scope",
        "worker_sha256",
        "image_identity",
        "grant_key_fingerprint",
        "authorization",
        "anomaly_authorization_input",
    }
)


def issue_scoped_execution_grant(
    private_key,
    binding,
    principal,
    trust_version,
    admission_scope,
    worker_sha256,
    image_identity,
    now,
    grant_id,
):
    if type(grant_id) is not str or len(grant_id) < 8 or len(grant_id) > 256:
        raise SecurityError("GRANT_ID")
    if type(admission_scope) is not str or not admission_scope or len(admission_scope) > 256:
        raise SecurityError("GRANT_SCOPE")
    if type(worker_sha256) is not str or len(worker_sha256) != 64:
        raise SecurityError("GRANT_WORKER_BINDING")
    if type(image_identity) is not str or not image_identity.startswith("sha256:") or len(image_identity) != 71:
        raise SecurityError("GRANT_IMAGE_BINDING")
    public = public_key_bytes(private_key)
    key_fingerprint = public_fingerprint(public)
    payload = {
        "schema": "guardian.execution-grant.v2",
        "grant_id": grant_id,
        "not_before": int(now),
        "expires_at": int(now) + 60,
        "subject": principal.subject,
        "role": principal.role,
        "wallet": principal.wallet,
        "binding": binding.as_dict(),
        "binding_sha256": binding.digest(),
        "trust_version": trust_version,
        "admission_scope": admission_scope,
        "worker_sha256": worker_sha256,
        "image_identity": image_identity,
        "grant_key_fingerprint": key_fingerprint,
        "authorization": "ALLOW",
        "anomaly_authorization_input": False,
    }
    encoded = canonical_json_bytes(payload)
    signature = private_key.sign(encoded)
    return {
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key_fingerprint": key_fingerprint,
    }


def verify_scoped_execution_grant(
    grant,
    public_key,
    now,
    expected_scope,
    expected_binding,
    expected_worker_sha256,
    expected_image_identity,
    expected_trust_version,
):
    if type(grant) is not dict or set(grant) != GRANT_FIELDS:
        raise SecurityError("GRANT_SHAPE")
    payload = grant.get("payload")
    if type(payload) is not dict or set(payload) != PAYLOAD_FIELDS:
        raise SecurityError("GRANT_PAYLOAD")
    try:
        signature = base64.b64decode(grant["signature"], validate=True)
        public_key.verify(signature, canonical_json_bytes(payload))
    except (ValueError, TypeError, InvalidSignature) as error:
        raise SecurityError("GRANT_SIGNATURE") from error
    public_bytes = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    expected_key_fingerprint = public_fingerprint(public_bytes)
    if (
        grant["public_key_fingerprint"] != expected_key_fingerprint
        or payload["grant_key_fingerprint"] != expected_key_fingerprint
    ):
        raise SecurityError("GRANT_KEY_BINDING")
    if payload["schema"] != "guardian.execution-grant.v2":
        raise SecurityError("GRANT_VERSION")
    if payload["admission_scope"] != expected_scope:
        raise SecurityError("GRANT_SCOPE")
    if payload["worker_sha256"] != expected_worker_sha256:
        raise SecurityError("GRANT_WORKER_BINDING")
    if payload["image_identity"] != expected_image_identity:
        raise SecurityError("GRANT_IMAGE_BINDING")
    if payload["trust_version"] != expected_trust_version:
        raise SecurityError("GRANT_TRUST_BINDING")
    if payload["authorization"] != "ALLOW" or payload["anomaly_authorization_input"] is not False:
        raise SecurityError("GRANT_AUTHORIZATION")
    if type(payload["not_before"]) is not int or type(payload["expires_at"]) is not int:
        raise SecurityError("GRANT_TIME_TYPE")
    if now < payload["not_before"] or now >= payload["expires_at"]:
        raise SecurityError("GRANT_TIME")
    if payload["expires_at"] - payload["not_before"] != 60:
        raise SecurityError("GRANT_LIFETIME")
    if (
        payload["binding"] != expected_binding.as_dict()
        or payload["binding_sha256"] != expected_binding.digest()
    ):
        raise SecurityError("GRANT_REQUEST_BINDING")
    digest = hashlib.sha256(canonical_json_bytes(grant)).hexdigest()
    return payload, digest
