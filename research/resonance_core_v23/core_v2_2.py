"""Advisory V2.1 resource detector plus a signed, causal IPC observation."""
from dataclasses import dataclass
import json
import re

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


VERSION = "resonance-core-v2.2-experimental"
DOMAIN = b"Resonance IPC observation v1\x00"
CONFIG = {"timeout_streak": 2, "recovery_streak": 2, "slow_latency_pct": 85}
FIELDS = {"run", "episode", "seq", "sent_ns", "deadline_ns", "cutoff_ns", "received_ns"}


def encoded(payload):
    return DOMAIN + json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@dataclass(frozen=True)
class Context:
    run: str
    episode: str
    seq: int
    cutoff_ns: int


def classify(envelope, key, context, deadline_ns):
    if envelope is None:
        return "UNKNOWN", None, "OBSERVATION_MISSING"
    try:
        if set(envelope) != {"payload", "signature"}:
            raise ValueError
        p, signature = envelope["payload"], envelope["signature"]
        if set(p) != FIELDS or not re.fullmatch(r"[a-f0-9]{128}", signature):
            raise ValueError
        key.verify(encoded(p), bytes.fromhex(signature))
        for field in ("seq", "sent_ns", "deadline_ns", "cutoff_ns"):
            if type(p[field]) is not int:
                raise ValueError
        if (p["run"], p["episode"], p["seq"], p["cutoff_ns"]) != (
            context.run, context.episode, context.seq, context.cutoff_ns
        ):
            return "UNKNOWN", None, "OBSERVATION_CONTEXT"
        got = p["received_ns"]
        if (p["seq"] < 0 or not 0 <= p["sent_ns"] <= p["cutoff_ns"]
                or p["deadline_ns"] - p["sent_ns"] != deadline_ns
                or (got is not None and (type(got) is not int or not p["sent_ns"] <= got <= p["cutoff_ns"]))):
            return "UNKNOWN", None, "OBSERVATION_TIME"
    except (BadSignatureError, KeyError, TypeError, ValueError):
        return "UNKNOWN", None, "OBSERVATION_UNTRUSTED"
    if got is None:
        if p["cutoff_ns"] < p["deadline_ns"]:
            return "UNKNOWN", None, "DEADLINE_PENDING"
        return "NO_RESPONSE_BY_CUTOFF", None, None
    latency = got - p["sent_ns"]
    return ("LATE" if latency > deadline_ns else "ON_TIME"), latency, None


class IPCState:
    def __init__(self, trusted_public_hex, deadline_ns):
        self.key = VerifyKey(bytes.fromhex(trusted_public_hex))
        if type(deadline_ns) is not int or deadline_ns <= 0:
            raise ValueError("INVALID_DEADLINE")
        self.deadline_ns = deadline_ns
        self.previous = None
        self.timeouts = self.healthy = self.slow = 0
        self.alarm = False

    def step(self, envelope, context):
        prior = self.previous
        if prior is not None and (
            (context.run, context.episode) != (prior.run, prior.episode)
            or context.seq <= prior.seq or context.cutoff_ns <= prior.cutoff_ns
        ):
            return self.unknown("NONMONOTONIC_CONTEXT")
        self.previous = context
        if (prior is None and context.seq != 0) or (prior is not None and context.seq != prior.seq + 1):
            return self.unknown("SEQUENCE_GAP")
        status, latency, reason = classify(envelope, self.key, context, self.deadline_ns)
        if reason:
            return self.unknown(reason)
        breach = status != "ON_TIME"
        self.timeouts = self.timeouts + 1 if breach else 0
        self.healthy = self.healthy + 1 if not breach else 0
        slow = not breach and latency * 100 >= self.deadline_ns * CONFIG["slow_latency_pct"]
        self.slow = self.slow + 1 if slow else 0
        recovery = self.alarm and self.healthy >= CONFIG["recovery_streak"]
        if recovery:
            self.alarm = False
        if self.timeouts >= CONFIG["timeout_streak"]:
            self.alarm = True
        return {
            "status": status, "reason": None, "latency_ns": latency,
            "deadline_violation": breach, "response_unobserved": status == "NO_RESPONSE_BY_CUTOFF",
            "consecutive_timeouts": self.timeouts, "consecutive_slow": self.slow,
            "recovered": recovery, "alarm": self.alarm,
        }

    def unknown(self, reason):
        self.timeouts = self.healthy = self.slow = 0
        return {
            "status": "UNKNOWN", "reason": reason, "latency_ns": None,
            "deadline_violation": None, "response_unobserved": None,
            "consecutive_timeouts": None, "consecutive_slow": None,
            "recovered": None, "alarm": None,
        }


class Core:
    def __init__(self, resource_core, trusted_public_hex, deadline_ns):
        self.resource_core = resource_core
        self.resource_state = resource_core.State()
        self.ipc = IPCState(trusted_public_hex, deadline_ns)

    def decide(self, features, envelope, context):
        ipc = self.ipc.step(envelope, context)
        self.resource_state, resource = self.resource_core.decide(self.resource_state, features)
        if ipc["status"] == "UNKNOWN":
            action = "UNKNOWN/HOLD"
        elif ipc["alarm"] and resource["action"] == "OBSERVE":
            action = "INVESTIGATE_CHANGE"
        else:
            action = resource["action"]
        return {"model_version": VERSION, "action": action, "ipc": ipc}
