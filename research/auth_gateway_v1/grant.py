"""Short-lived Ed25519 execution grants; grants never create authorization."""

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_json_bytes, public_fingerprint
from .errors import SecurityError


def generate_grant_key():
    return Ed25519PrivateKey.generate()


def public_key_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def issue_execution_grant(private_key, binding, principal, trust_version, now, grant_id):
    if type(grant_id) is not str or len(grant_id) < 8:
        raise SecurityError("GRANT_ID")
    payload = {
        "schema": "guardian.execution-grant.v1",
        "grant_id": grant_id,
        "not_before": int(now),
        "expires_at": int(now) + 60,
        "subject": principal.subject,
        "role": principal.role,
        "wallet": principal.wallet,
        "binding": binding.as_dict(),
        "binding_sha256": binding.digest(),
        "trust_version": trust_version,
        "authorization": "ALLOW",
        "anomaly_authorization_input": False,
    }
    encoded = canonical_json_bytes(payload)
    signature = private_key.sign(encoded)
    public = public_key_bytes(private_key)
    return {
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key_fingerprint": public_fingerprint(public),
    }


def verify_execution_grant(grant, public_key, nonce_store, now, expected_binding=None):
    if type(grant) is not dict or set(grant) != {"payload", "signature", "public_key_fingerprint"}:
        raise SecurityError("GRANT_SHAPE")
    payload = grant["payload"]
    if type(payload) is not dict:
        raise SecurityError("GRANT_PAYLOAD")
    try:
        signature = base64.b64decode(grant["signature"], validate=True)
        public_key.verify(signature, canonical_json_bytes(payload))
    except (ValueError, TypeError, InvalidSignature) as error:
        raise SecurityError("GRANT_SIGNATURE") from error
    if payload.get("schema") != "guardian.execution-grant.v1":
        raise SecurityError("GRANT_VERSION")
    if grant["public_key_fingerprint"] != public_fingerprint(
        public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ):
        raise SecurityError("GRANT_KEY_BINDING")
    if payload.get("authorization") != "ALLOW" or payload.get("anomaly_authorization_input") is not False:
        raise SecurityError("GRANT_AUTHORIZATION")
    if type(payload.get("not_before")) is not int or type(payload.get("expires_at")) is not int:
        raise SecurityError("GRANT_TIME_TYPE")
    if now < payload["not_before"] or now >= payload["expires_at"]:
        raise SecurityError("GRANT_TIME")
    if payload["expires_at"] - payload["not_before"] != 60:
        raise SecurityError("GRANT_LIFETIME")
    if expected_binding is not None:
        if payload.get("binding") != expected_binding.as_dict() or payload.get("binding_sha256") != expected_binding.digest():
            raise SecurityError("GRANT_REQUEST_BINDING")
    nonce_store.consume("execution-grant", payload.get("grant_id"), now, payload["expires_at"])
    return payload
