"""Strict synthetic-only replay envelope; no URLs, commands, wallets or secrets."""

from pathlib import Path

from research.rare_event_evidence_v0.model import canonical_bytes, digest, strict_json

SCHEMA = "guardian.gateway-abuse-event.v0"
REPORT_SCHEMA = "guardian.gateway-abuse-replay-report.v0"
ORIGIN = "synthetic"
FIELDS = frozenset({
    "schema", "origin", "seq", "tick", "principal", "wallet", "token_role",
    "token_verified", "operation", "agent", "registry_owner", "ownership_proof",
    "service", "destination", "payload",
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
# These are wholly synthetic aliases. No Ethereum addresses or real target names.
PRINCIPALS = frozenset({"guest", "legit", "probe", "service", "telegram"})
WALLETS = frozenset({"none", "wallet-legit", "wallet-probe", "wallet-admin", "wallet-service", "wallet-telegram"})
AGENTS = frozenset({"none", "agent-legit", "agent-probe", "agent-unknown"})
MAX_EVENTS = 2_000
MAX_FILE_BYTES = 1_000_000
MAX_LINE_BYTES = 2_048


class ReplayInputError(ValueError):
    """Untrusted input: do not emit a successful security verdict."""


def validate_events(events):
    if not isinstance(events, list) or not (1 <= len(events) <= MAX_EVENTS):
        raise ReplayInputError("event list must be non-empty and bounded")
    previous_tick = -1
    for i, item in enumerate(events, 1):
        if type(item) is not dict or set(item) != FIELDS:
            raise ReplayInputError(f"event {i}: exact schema fields required")
        if item["schema"] != SCHEMA or item["origin"] != ORIGIN:
            raise ReplayInputError(f"event {i}: only synthetic v0 input is accepted")
        if type(item["seq"]) is not int or item["seq"] != i:
            raise ReplayInputError(f"event {i}: noncontiguous sequence")
        if type(item["tick"]) is not int or not (0 <= item["tick"] <= 10_000_000):
            raise ReplayInputError(f"event {i}: invalid synthetic tick")
        if item["tick"] <= previous_tick:
            raise ReplayInputError(f"event {i}: ticks must be strictly increasing")
        previous_tick = item["tick"]
        for key, allowed in (("principal", PRINCIPALS), ("wallet", WALLETS),
                             ("token_role", ROLES), ("operation", OPERATIONS),
                             ("agent", AGENTS), ("registry_owner", WALLETS),
                             ("service", SERVICES), ("destination", DESTINATIONS),
                             ("payload", PAYLOADS)):
            if type(item[key]) is not str or item[key] not in allowed:
                raise ReplayInputError(f"event {i}: invalid {key}")
        for key in ("token_verified", "ownership_proof"):
            if type(item[key]) is not bool:
                raise ReplayInputError(f"event {i}: {key} requires bool")
        if item["operation"] == "EXTERNAL_EFFECT" and (item["service"] != "UNKNOWN" or item["payload"] != "UNKNOWN"):
            raise ReplayInputError(f"event {i}: unknown external effect is out of scope")
    return events


def encode_events(events):
    validate_events(events)
    return b"".join(canonical_bytes(event) + b"\n" for event in events)


def read_events(path):
    try:
        path = Path(path)
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ReplayInputError("input exceeds byte limit")
        raw = path.read_bytes()
    except OSError as exc:
        raise ReplayInputError(f"cannot read events: {exc}") from exc
    if not raw or len(raw) > MAX_FILE_BYTES:
        raise ReplayInputError("invalid event byte count")
    lines = raw.splitlines()
    if not (1 <= len(lines) <= MAX_EVENTS):
        raise ReplayInputError("invalid record count")
    items = []
    for i, line in enumerate(lines, 1):
        if not line or len(line) > MAX_LINE_BYTES:
            raise ReplayInputError(f"event {i}: blank or oversized")
        try:
            items.append(strict_json(line.decode("utf-8")))
        except (UnicodeError, ValueError) as exc:
            raise ReplayInputError(f"event {i}: invalid strict JSON: {exc}") from exc
    return validate_events(items)


def read_report(path):
    try:
        p = Path(path)
        if not (0 < p.stat().st_size <= MAX_FILE_BYTES):
            raise ReplayInputError("report byte limit")
        return strict_json(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReplayInputError(f"cannot parse report: {exc}") from exc
