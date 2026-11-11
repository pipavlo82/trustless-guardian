"""Strict, bounded synthetic event format and deterministic evidence digests."""

import hashlib
import json
import re
from pathlib import Path

EVENT_SCHEMA = "guardian.rare-event.v0"
REPORT_SCHEMA = "guardian.rare-event-report.v0"
ACTIONS = ("READ", "WRITE", "DELETE", "POLICY_CHANGE")
OUTCOMES = ("ALLOW", "DENY", "RECOVERY_REQUIRED")
FIELDS = frozenset({"schema", "origin", "seq", "agent", "resource", "action", "outcome", "policy_revision"})
ID_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
RESOURCE_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_./:-]{0,127}\Z")
CONFIG = {
    "rare_threshold_denominator": 32,
    "deny_window": 6,
    "deny_count": 4,
    "transition_window": 6,
}
MAX_RECORDS = 20_000
MAX_FILE_BYTES = 5_000_000
MAX_LINE_BYTES = 2_048
MIN_BASELINE = 32


class InputError(ValueError):
    """Malformed or out-of-scope input; never interpreted as a security verdict."""


def _reject_constant(value):
    raise InputError(f"non-finite JSON constant: {value}")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(text):
    try:
        return json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_unique_pairs)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise InputError(f"invalid JSON: {exc}") from exc


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def validate_event(event, seq):
    if not isinstance(event, dict) or set(event) != FIELDS:
        raise InputError(f"event {seq}: exact field set required")
    if event["schema"] != EVENT_SCHEMA or event["origin"] != "synthetic":
        raise InputError(f"event {seq}: only synthetic v0 events are accepted")
    if type(event["seq"]) is not int or event["seq"] != seq:
        raise InputError(f"event {seq}: sequence must be contiguous from 1")
    if type(event["policy_revision"]) is not int or not (0 <= event["policy_revision"] <= 1_000_000):
        raise InputError(f"event {seq}: invalid policy revision")
    if not isinstance(event["agent"], str) or not ID_PATTERN.fullmatch(event["agent"]):
        raise InputError(f"event {seq}: invalid agent")
    if (not isinstance(event["resource"], str) or not RESOURCE_PATTERN.fullmatch(event["resource"])
            or ".." in event["resource"]):
        raise InputError(f"event {seq}: invalid resource identifier")
    if event["action"] not in ACTIONS or event["outcome"] not in OUTCOMES:
        raise InputError(f"event {seq}: invalid action or outcome")
    return event


def read_events(path, *, baseline=False):
    path = Path(path)
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise InputError("input exceeds byte limit")
        data = path.read_bytes()
    except OSError as exc:
        raise InputError(f"cannot read event file: {exc}") from exc
    if len(data) > MAX_FILE_BYTES:
        raise InputError("input exceeds byte limit")
    lines = data.splitlines()
    if len(lines) > MAX_RECORDS:
        raise InputError("too many events")
    if baseline and len(lines) < MIN_BASELINE:
        raise InputError(f"baseline requires at least {MIN_BASELINE} events")
    if not lines:
        raise InputError("empty event stream")
    events = []
    for seq, line in enumerate(lines, 1):
        if not line or len(line) > MAX_LINE_BYTES:
            raise InputError(f"event {seq}: blank or oversized line")
        try:
            item = strict_json(line.decode("utf-8"))
        except UnicodeError as exc:
            raise InputError(f"event {seq}: non-UTF-8 input") from exc
        events.append(validate_event(item, seq))
    return events


def encode_events(events):
    for seq, event in enumerate(events, 1):
        validate_event(event, seq)
    return b"".join(canonical_bytes(event) + b"\n" for event in events)
