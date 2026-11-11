"""Wholly synthetic functional fixtures. Held-out evaluation is elsewhere."""

from .model import ORIGIN, SCHEMA


def event(seq, tick, *, subject="owner-a", token_subject=None, wallet="wallet-a", token_wallet=None,
          role="OWNER", verified=True, operation="READ_AGENT", agent="agent-a",
          claimed_owner="owner-a", proof=True, service="GATEWAY", destination="INTERNAL", payload="SAFE"):
    return {
        "schema": SCHEMA, "origin": ORIGIN, "seq": seq, "tick": tick,
        "request_subject": subject, "token_subject": subject if token_subject is None else token_subject,
        "wallet": wallet, "token_wallet": wallet if token_wallet is None else token_wallet,
        "token_role": role, "token_verified": verified, "operation": operation,
        "agent": agent, "claimed_owner": claimed_owner, "ownership_proof": proof,
        "service": service, "destination": destination, "payload": payload,
    }


def health(seq, tick):
    return event(seq, tick, subject="guest", wallet="none", role="ANON", verified=False,
                 operation="HEALTH", agent="none", claimed_owner="none", proof=False)


def admin(seq, tick, operation="ADMIN_WRITE", *, agent="agent-a", owner="owner-a", destination="INTERNAL"):
    if operation == "REGISTER_MCP":
        agent, owner, destination = "none", "none", "APPROVED"
    return event(seq, tick, subject="admin", wallet="wallet-admin", role="ADMIN", operation=operation,
                 agent=agent, claimed_owner=owner, proof=False, destination=destination)


def service(seq, tick, operation="RUN_TOOL", *, agent="agent-a", owner="owner-a"):
    bindings = {
        "RUN_TOOL": ("svc-runner", "wallet-runner", "RUNNER", "INTERNAL"),
        "MCP_CALL": ("svc-mcp", "wallet-mcp", "MCP", "APPROVED"),
        "TELEGRAM_CALL": ("svc-telegram", "wallet-telegram", "TELEGRAM", "INTERNAL"),
    }
    subject, wallet, system, destination = bindings[operation]
    return event(seq, tick, subject=subject, wallet=wallet, role="SERVICE", operation=operation,
                 agent=agent, claimed_owner=owner, proof=False, service=system, destination=destination)


def functional_trace():
    return [
        health(1, 0),
        event(2, 10),
        admin(3, 20),
        service(4, 30, "RUN_TOOL"),
        event(5, 40, subject="attacker", wallet="wallet-admin", token_subject="attacker",
              token_wallet="wallet-admin", role="ADMIN", operation="ADMIN_WRITE"),
        event(6, 50, subject="owner-a", wallet="wallet-a", token_subject="owner-b",
              token_wallet="wallet-a", role="OWNER", operation="READ_AGENT"),
        event(7, 60, subject="svc-runner", wallet="wallet-runner", role="SERVICE", operation="RUN_TOOL",
              agent="agent-a", claimed_owner="owner-b", proof=False, service="RUNNER", payload="UNSAFE_COMMAND"),
    ]

