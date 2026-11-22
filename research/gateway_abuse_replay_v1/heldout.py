"""Predeclared synthetic holdout families, independent of functional_trace().

Labels are returned separately and are never included in detector input.
"""

from .fixtures import admin, event, health, service


def _renumber(rows, offset):
    output = []
    for index, row in enumerate(rows, 1):
        item = dict(row)
        item["seq"] = index
        item["tick"] = offset + index * 10
        output.append(item)
    return output


def benign_stream(seed):
    rows = [
        health(1, 1), event(2, 2), event(3, 3, operation="SKILL_TEST"),
        admin(4, 4, "CREATE_SKILL", agent="agent-b", owner="owner-b"),
        admin(5, 5, "REGISTER_MCP"), service(6, 6, "MCP_CALL", agent="agent-b", owner="owner-b"),
        service(7, 7, "RUN_TOOL"), service(8, 8, "TELEGRAM_CALL"),
        event(9, 9, subject="owner-b", wallet="wallet-b", agent="agent-b", claimed_owner="owner-b"),
        event(10, 10), event(11, 11, operation="SKILL_TEST"), event(12, 12),
    ]
    # Legitimate owner reads are intentionally close together; v1 burst logic
    # excludes non-sensitive reads while v0's principal-only burst can alert.
    rows[9]["tick"], rows[10]["tick"], rows[11]["tick"] = 100, 101, 102
    shifted = []
    for index, row in enumerate(rows, 1):
        item = dict(row); item["seq"] = index; item["tick"] += seed * 1000
        shifted.append(item)
    return shifted, []


def attack_stream(kind, seed):
    rows = [health(1, 1), event(2, 2), event(3, 3, operation="SKILL_TEST")]
    if kind == "role":
        bad = event(4, 4, subject="owner-a", wallet="wallet-a", role="OWNER", operation="ADMIN_WRITE")
    elif kind == "subject":
        bad = event(4, 4, token_subject="owner-b")
    elif kind == "wallet":
        bad = event(4, 4, token_wallet="wallet-b")
    elif kind == "resource":
        bad = event(4, 4, agent="agent-b", claimed_owner="owner-a")
    elif kind == "registration":
        bad = event(4, 4, operation="REGISTER_AGENT", proof=False)
    elif kind == "mcp":
        bad = service(4, 4, "MCP_CALL"); bad["destination"] = "PRIVATE_LAN"
    elif kind == "tool":
        bad = service(4, 4, "RUN_TOOL"); bad["payload"] = "UNSAFE_COMMAND"
    elif kind == "cross-service":
        bad = service(4, 4, "RUN_TOOL"); bad["request_subject"] = bad["token_subject"] = "svc-mcp"; bad["wallet"] = bad["token_wallet"] = "wallet-mcp"
    else:
        raise ValueError(kind)
    rows.extend([bad, event(5, 5), health(6, 6)])
    shifted = _renumber(rows, 20_000 + seed * 1000)
    return shifted, [4]


def corpus():
    benign = [(f"benign-admin-owner-service-{i}", *benign_stream(i)) for i in range(4)]
    kinds = ("role", "subject", "wallet", "resource", "registration", "mcp", "tool", "cross-service")
    attacks = [(f"attack-{kind}", *attack_stream(kind, i)) for i, kind in enumerate(kinds)]
    return benign + attacks

