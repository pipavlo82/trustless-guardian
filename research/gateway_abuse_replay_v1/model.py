"""Strict synthetic v1 input model. No live identities, URLs, or commands."""

from pathlib import Path

from research.rare_event_evidence_v0.model import canonical_bytes, digest, strict_json

SCHEMA = "guardian.gateway-abuse-event.v1"
REPORT_SCHEMA = "guardian.gateway-abuse-replay-report.v1"
ORIGIN = "synthetic"
FIELDS = frozenset({
    "schema", "origin", "seq", "tick", "request_subject", "token_subject",
    "wallet", "token_wallet", "token_role", "token_verified", "operation",
    "agent", "claimed_owner", "ownership_proof", "service", "destination", "payload",
})
OPERATIONS = frozenset({
    "HEALTH", "READ_AGENT", "REGISTER_AGENT", "ADMIN_WRITE", "CREATE_SKILL",
    "REGISTER_MCP", "SKILL_TEST", "MCP_CALL", "RUN_TOOL", "TELEGRAM_CALL",
    "EXTERNAL_EFFECT",
})
ROLES = frozenset({"ANON", "OWNER", "ADMIN", "SERVICE"})
SERVICES = frozenset({"GATEWAY", "RUNNER", "MCP", "TELEGRAM", "UNKNOWN"})
DESTINATIONS = frozenset({"INTERNAL", "APPROVED", "EXTERNAL", "PRIVATE_LAN", "UNKNOWN"})
PAYLOADS = frozenset({"SAFE", "UNSAFE_COMMAND", "DATA_EXPORT", "REMOTE_MCP", "UNKNOWN"})
SUBJECT_WALLETS = {
    "guest": "none",
    "owner-a": "wallet-a",
    "owner-b": "wallet-b",
    "admin": "wallet-admin",
    "svc-runner": "wallet-runner",
    "svc-mcp": "wallet-mcp",
    "svc-telegram": "wallet-telegram",
    "attacker": "wallet-attacker",
}
AGENT_OWNERS = {
    "agent-a": "owner-a",
    "agent-b": "owner-b",
    "agent-pending-a": "owner-a",
    "agent-admin": "admin",
}
SUBJECTS = frozenset(SUBJECT_WALLETS)
WALLETS = frozenset(SUBJECT_WALLETS.values())
AGENTS = frozenset({"none", *AGENT_OWNERS})
OWNERS = frozenset({"none", "owner-a", "owner-b", "admin"})
MAX_EVENTS = 4_000
MAX_FILE_BYTES = 2_000_000
MAX_LINE_BYTES = 2_048


class ReplayInputError(ValueError):
    """Malformed or out-of-scope input. Never a successful security result."""


def validate_events(events):
    if type(events) is not list or not (1 <= len(events) <= MAX_EVENTS):
        raise ReplayInputError("event list must be non-empty and bounded")
    previous_tick = -1
    enum_fields = (
        ("request_subject", SUBJECTS), ("token_subject", SUBJECTS),
        ("wallet", WALLETS), ("token_wallet", WALLETS), ("token_role", ROLES),
        ("operation", OPERATIONS), ("agent", AGENTS), ("claimed_owner", OWNERS),
        ("service", SERVICES), ("destination", DESTINATIONS), ("payload", PAYLOADS),
    )
    for index, event in enumerate(events, 1):
        if type(event) is not dict or set(event) != FIELDS:
            raise ReplayInputError(f"event {index}: exact schema fields required")
        if event["schema"] != SCHEMA or event["origin"] != ORIGIN:
            raise ReplayInputError(f"event {index}: only synthetic v1 input is accepted")
        if type(event["seq"]) is not int or event["seq"] != index:
            raise ReplayInputError(f"event {index}: noncontiguous sequence")
        if type(event["tick"]) is not int or not (0 <= event["tick"] <= 20_000_000):
            raise ReplayInputError(f"event {index}: invalid synthetic tick")
        if event["tick"] <= previous_tick:
            raise ReplayInputError(f"event {index}: ticks must be strictly increasing")
        previous_tick = event["tick"]
        for name, allowed in enum_fields:
            if type(event[name]) is not str or event[name] not in allowed:
                raise ReplayInputError(f"event {index}: invalid {name}")
        for name in ("token_verified", "ownership_proof"):
            if type(event[name]) is not bool:
                raise ReplayInputError(f"event {index}: {name} requires bool")
        if event["operation"] == "EXTERNAL_EFFECT" and (
            event["service"] != "UNKNOWN" or event["destination"] != "UNKNOWN" or event["payload"] != "UNKNOWN"
        ):
            raise ReplayInputError(f"event {index}: external effect must remain unknown")
    return events


def encode_events(events):
    validate_events(events)
    return b"".join(canonical_bytes(event) + b"\n" for event in events)


def read_events(path):
    try:
        path = Path(path)
        if not (0 < path.stat().st_size <= MAX_FILE_BYTES):
            raise ReplayInputError("invalid input byte count")
        raw = path.read_bytes()
    except OSError as exc:
        raise ReplayInputError(f"cannot read events: {exc}") from exc
    lines = raw.splitlines()
    if not (1 <= len(lines) <= MAX_EVENTS):
        raise ReplayInputError("invalid record count")
    events = []
    for index, line in enumerate(lines, 1):
        if not line or len(line) > MAX_LINE_BYTES:
            raise ReplayInputError(f"event {index}: blank or oversized")
        try:
            events.append(strict_json(line.decode("utf-8")))
        except (UnicodeError, ValueError) as exc:
            raise ReplayInputError(f"event {index}: invalid strict JSON: {exc}") from exc
    return validate_events(events)


def read_report(path):
    try:
        path = Path(path)
        if not (0 < path.stat().st_size <= MAX_FILE_BYTES):
            raise ReplayInputError("invalid report byte count")
        return strict_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReplayInputError(f"cannot parse report: {exc}") from exc

