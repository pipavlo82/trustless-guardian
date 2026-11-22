"""Self-contained, wholly invented events with separate synthetic truth annotations."""

from pathlib import Path

from .model import ORIGIN, SCHEMA, encode_events


def event(seq, tick, *, principal="legit", wallet="wallet-legit", role="OWNER", verified=True,
          operation="READ_AGENT", agent="agent-legit", registry_owner="wallet-legit", proof=True,
          service="GATEWAY", destination="INTERNAL", payload="SAFE"):
    return {
        "schema": SCHEMA, "origin": ORIGIN, "seq": seq, "tick": tick,
        "principal": principal, "wallet": wallet, "token_role": role,
        "token_verified": verified, "operation": operation, "agent": agent,
        "registry_owner": registry_owner, "ownership_proof": proof,
        "service": service, "destination": destination, "payload": payload,
    }


def attack_fixture():
    """Sequence constructed to test an early signal before the first denied request."""
    probe = {"principal": "probe", "wallet": "wallet-probe", "registry_owner": "wallet-probe", "agent": "agent-probe"}
    series = [
        event(1, 0, principal="guest", wallet="none", role="ANON", verified=False, operation="HEALTH", agent="none", registry_owner="none", proof=False),
        event(2, 10, operation="SKILL_TEST", **probe),
        event(3, 11, operation="SKILL_TEST", **probe),
        event(4, 12, operation="SKILL_TEST", **probe),
        event(5, 13, operation="ADMIN_WRITE", **probe),
        event(6, 14, operation="REGISTER_AGENT", agent="agent-unknown", proof=False,
              principal="probe", wallet="wallet-probe", registry_owner="wallet-probe"),
        event(7, 15, operation="CREATE_SKILL", **probe),
        event(8, 16, operation="REGISTER_MCP", destination="EXTERNAL", payload="REMOTE_MCP", **probe),
        event(9, 17, operation="SKILL_TEST", **probe),
        event(10, 18, operation="MCP_CALL", service="MCP", destination="EXTERNAL", payload="DATA_EXPORT", **probe),
        event(11, 19, principal="service", wallet="wallet-service", role="SERVICE", agent="none", registry_owner="none",
              proof=False, operation="RUN_TOOL", service="RUNNER", payload="UNSAFE_COMMAND"),
        event(12, 20, operation="TELEGRAM_CALL", service="TELEGRAM", **probe),
        event(13, 21, principal="probe", wallet="wallet-probe", agent="none", registry_owner="none",
              role="ANON", verified=False, proof=False, operation="EXTERNAL_EFFECT", service="UNKNOWN",
              destination="UNKNOWN", payload="UNKNOWN"),
        event(14, 30, principal="guest", wallet="none", role="ANON", verified=False,
              operation="HEALTH", agent="none", registry_owner="none", proof=False),
    ]
    # Labels are separate from the event stream and NEVER used by either detector.
    return series, list(range(2, 14))


def benign_fixture(seed=0):
    series = []
    roles = ("READ_AGENT", "HEALTH", "REGISTER_AGENT", "CREATE_SKILL", "REGISTER_MCP",
             "RUN_TOOL", "MCP_CALL", "TELEGRAM_CALL", "SKILL_TEST")
    for i in range(1, 46):
        op = roles[(i + seed) % len(roles)]
        kw = {}
        if op == "HEALTH":
            kw = {"principal": "guest", "wallet": "none", "role": "ANON", "verified": False,
                  "agent": "none", "registry_owner": "none", "proof": False}
        elif op in {"CREATE_SKILL", "REGISTER_MCP"}:
            kw = {"wallet": "wallet-admin", "role": "ADMIN", "destination": "APPROVED"}
        elif op in {"RUN_TOOL", "MCP_CALL", "TELEGRAM_CALL"}:
            kw = {"principal": "service" if op != "TELEGRAM_CALL" else "telegram",
                  "wallet": "wallet-service" if op != "TELEGRAM_CALL" else "wallet-telegram",
                  "role": "SERVICE", "agent": "none", "registry_owner": "none", "proof": False,
                  "service": {"RUN_TOOL": "RUNNER", "MCP_CALL": "MCP", "TELEGRAM_CALL": "TELEGRAM"}[op],
                  "destination": "APPROVED" if op == "MCP_CALL" else "INTERNAL"}
        # Deliberate legitimate short burst -> measurable synthetic false positive.
        if i in (21, 22, 23):
            op, kw = "SKILL_TEST", {}
        tick = i * 8 + seed * 1000
        if i == 22:
            tick = 21 * 8 + 1 + seed * 1000
        if i == 23:
            tick = 21 * 8 + 2 + seed * 1000
        series.append(event(i, tick, operation=op, **kw))
    return series, []


def attack_holdout(seed=0):
    series, mal = attack_fixture()
    rows = []
    removed = {3} if seed % 3 == 1 else set()
    for record in series:
        if record["seq"] in removed:
            continue
        item = dict(record)
        item["seq"] = len(rows) + 1
        item["tick"] = record["tick"] + seed * 1000
        rows.append(item)
    positives = [r["seq"] for r in rows if r["seq"] != 1 and r["operation"] != "HEALTH"]
    return rows, positives


def holdout_corpus():
    return [("benign-" + str(i), *benign_fixture(i)) for i in range(6)] + [
        ("attack-" + str(i), *attack_holdout(i)) for i in range(6)
    ]


def write_fixtures(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    attack, _ = attack_fixture()
    benign, _ = benign_fixture()
    (directory / "attack.synthetic.jsonl").write_bytes(encode_events(attack))
    (directory / "benign.synthetic.jsonl").write_bytes(encode_events(benign))
    return directory
