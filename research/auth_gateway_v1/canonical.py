"""Canonical JSON and digest helpers used only for local binding evidence."""

import hashlib
import json

from .errors import SecurityError


def _validate_json(value):
    if value is None or type(value) in {bool, int, str}:
        return
    if type(value) is list:
        for item in value:
            _validate_json(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise SecurityError("JSON_KEY_TYPE")
            _validate_json(item)
        return
    raise SecurityError("JSON_VALUE_TYPE")


def canonical_json_bytes(value):
    _validate_json(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def sha256_hex(value):
    if type(value) is not bytes:
        raise TypeError("sha256 input must be bytes")
    return hashlib.sha256(value).hexdigest()


def public_fingerprint(value):
    return sha256_hex(value)[:24]
