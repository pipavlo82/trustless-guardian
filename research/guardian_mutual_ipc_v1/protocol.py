"""Ed25519 broker-origin authentication in the existing Guardian integer JSON domain.

Trust is provisioned out of band, never selected by a response. No execution API.
"""
import hashlib
import json
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from research.auth_gateway_v1.canonical import canonical_json_bytes

PROTOCOL = "guardian.mutual-ipc-auth.v1"
DOMAIN = b"GUARDIAN-BROKER-AUTH-V1\x00"
MAX_FRAME = 4096
TTL = 30
HEX32 = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-zA-Z0-9._:-]{1,100}\Z")
TRUST_FIELDS = {"schema", "broker_id", "trust_root_version", "key_id", "public_key", "revoked", "not_before", "expires_at"}
CONTEXT_FIELDS = {"protocol", "session_id", "client_challenge", "broker_id", "trust_root_version", "key_id", "channel_id"}
PAYLOAD_FIELDS = CONTEXT_FIELDS | {"phase", "request_sha256", "issued_at", "expires_at", "response"}


class Refused(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(ok, code):
    if not ok:
        raise Refused(code)


def encode(value):
    return canonical_json_bytes(value)


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_FRAME, "FRAME_SIZE")
    def pairs(items):
        out = {}
        for k, v in items:
            require(k not in out, "DUPLICATE_MEMBER")
            out[k] = v
        return out
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
                           parse_float=lambda _: (_ for _ in ()).throw(Refused("FRAME_NUMBER")),
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused("FRAME_NUMBER")))
        require(encode(value) == raw, "FRAME_NONCANONICAL")
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError) as e:
        raise Refused("FRAME_MALFORMED") from e


def validate_trust(trust, now):
    require(type(trust) is dict and set(trust) == TRUST_FIELDS, "TRUST_MISSING_OR_SHAPE")
    require(trust["schema"] == "guardian.broker-trust.v1", "TRUST_VERSION")
    require(trust["revoked"] is False, "TRUST_REVOKED")
    require(all(type(trust[k]) is str and NAME.fullmatch(trust[k]) for k in ("broker_id", "key_id", "trust_root_version")), "TRUST_IDENTITY")
    require(type(trust["public_key"]) is str and HEX32.fullmatch(trust["public_key"]), "TRUST_KEY")
    require(type(now) is int and type(trust["not_before"]) is int and type(trust["expires_at"]) is int
            and trust["not_before"] <= now < trust["expires_at"], "TRUST_TIME")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(trust["public_key"]))


def validate_hello(hello, trust, channel_id):
    require(type(hello) is dict and set(hello) == CONTEXT_FIELDS | {"op", "agent_id"}, "HELLO_SHAPE")
    require(hello["protocol"] == PROTOCOL and hello["op"] == "HELLO" and hello["agent_id"] == "resonance-agent-v5", "HELLO_VERSION")
    require(all(type(hello[k]) is str and HEX32.fullmatch(hello[k]) for k in ("session_id", "client_challenge")), "HELLO_FRESHNESS")
    require(hello["channel_id"] == channel_id, "HELLO_CHANNEL")
    require(all(hello[k] == trust[k] for k in ("broker_id", "trust_root_version", "key_id")), "HELLO_AUTHORITY")


def sign_response(key, context, phase, request, response, now):
    payload = {k: context[k] for k in CONTEXT_FIELDS}
    payload.update(phase=phase, request_sha256=digest(request), issued_at=now,
                   expires_at=now + TTL, response=response)
    return {"payload": payload, "signature": key.sign(DOMAIN + encode(payload)).hex()}


def verify_response(envelope, trust, context, phase, request, now):
    key = validate_trust(trust, now)
    require(type(envelope) is dict and set(envelope) == {"payload", "signature"}, "AUTH_MISSING")
    p = envelope["payload"]
    require(type(p) is dict and set(p) == PAYLOAD_FIELDS, "AUTH_SHAPE")
    require(p["protocol"] == PROTOCOL, "AUTH_VERSION")
    require(p["session_id"] == context["session_id"], "AUTH_SESSION")
    require(p["client_challenge"] == context["client_challenge"], "AUTH_CHALLENGE")
    require(p["channel_id"] == context["channel_id"], "AUTH_CHANNEL")
    require(all(p[k] == trust[k] for k in ("broker_id", "trust_root_version", "key_id")), "AUTH_AUTHORITY")
    require(p["phase"] == phase, "AUTH_PHASE")
    require(p["request_sha256"] == digest(request), "AUTH_REQUEST")
    require(type(p["issued_at"]) is int and type(p["expires_at"]) is int and
            0 < p["expires_at"] - p["issued_at"] <= TTL and
            p["issued_at"] <= now < p["expires_at"], "AUTH_TIME")
    sig = envelope["signature"]
    require(type(sig) is str and re.fullmatch(r"[0-9a-f]{128}", sig), "AUTH_SIGNATURE_SHAPE")
    try:
        key.verify(bytes.fromhex(sig), DOMAIN + encode(p))
    except (InvalidSignature, ValueError) as e:
        raise Refused("AUTH_SIGNATURE") from e
    return p["response"]


def validate_response(phase, value):
    if phase == "hello":
        require(type(value) is dict and set(value) == {"verdict", "nonce", "observations_scaled", "scale", "tools_enabled"}, "RESPONSE_SHAPE")
        require(value["verdict"] == "SYNTHETIC_OBSERVATIONS" and value["tools_enabled"] is False
                and type(value["scale"]) is int and value["scale"] == 100
                and value["observations_scaled"] == [20, 30, 40]
                and all(type(x) is int for x in value["observations_scaled"])
                and type(value["nonce"]) is str and HEX32.fullmatch(value["nonce"]), "RESPONSE_SIGNALS")
    else:
        require(type(value) is dict and set(value) == {"verdict", "grant_issued", "tool_executed"}, "RESPONSE_SHAPE")
        require(value["verdict"] in ("HOLD_GUARDIAN_GRANT_REQUIRED", "DENY_REQUEST_OR_NONCE")
                and value["grant_issued"] is False and value["tool_executed"] is False, "RESPONSE_NOT_HOLD")


class ClientSession:
    """Per-connection one-shot phase consumption plus fresh unpredictable challenge."""
    def __init__(self, trust, channel_id, now, *, session_id=None, challenge=None, clock=time.monotonic):
        validate_trust(trust, now)
        require(type(channel_id) is str and re.fullmatch(r"guardian-resonance-[0-9a-f]{24}", channel_id), "CHANNEL")
        self.trust = dict(trust)
        self.context = {"protocol": PROTOCOL, "session_id": session_id or secrets.token_hex(32),
                        "client_challenge": challenge or secrets.token_hex(32), "channel_id": channel_id,
                        **{k: trust[k] for k in ("broker_id", "trust_root_version", "key_id")}}
        self.clock = clock
        self.started = clock()
        self.phase = "hello"
        self.hello = {**self.context, "op": "HELLO", "agent_id": "resonance-agent-v5"}
        validate_hello(self.hello, trust, channel_id)

    def accept(self, envelope, phase, request, now):
        require(self.phase == phase and phase in ("hello", "result"), "AUTH_REPLAY_OR_ORDER")
        # Any attempted response consumes this phase; refusal terminates the session.
        self.phase = "closed"
        require(0 <= self.clock() - self.started <= TTL, "AUTH_DEADLINE")
        value = verify_response(envelope, self.trust, self.context, phase, request, now)
        validate_response(phase, value)
        self.phase = "result" if phase == "hello" else "closed"
        return value
