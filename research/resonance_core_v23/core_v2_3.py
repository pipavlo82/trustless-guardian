"""V2.3 distinguishes a resource warning from a confirmed advisory incident."""
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from core_v2_2 import Context, IPCState
from support_v23 import RESOURCE_DOMAIN, RESOURCE_FIELDS, canonical, signals


VERSION = "resonance-core-v2.3-experimental"
CONFIG = {"resource_confirmation_ticks": 2}


def decode_resource(envelope, key, context, policy):
    if envelope is None:
        return None
    try:
        if set(envelope) != {"payload", "signature"}:
            return None
        payload = envelope["payload"]
        if set(payload) != {"run", "episode", "row"}:
            return None
        signature = bytes.fromhex(envelope["signature"])
        if signature.hex() != envelope["signature"]:
            return None
        key.verify(RESOURCE_DOMAIN + canonical(payload), signature)
        row = payload["row"]
        if set(row) != RESOURCE_FIELDS or any(type(v) is not int for v in row.values()):
            return None
        valid = (payload["run"], payload["episode"], row["seq"], row["monotonic_ns"]) == (
            context.run, context.episode, context.seq, context.cutoff_ns)
        bounds = (row["monotonic_ns"] > 0 and row["utc_ns"] > 0 and row["cpu_ns"] >= 0
                  and 0 < row["rss_bytes"] <= policy["maximum_process_rss_bytes"]
                  and 0 <= row["disk_used_bytes"] <= row["disk_total_bytes"] and row["disk_total_bytes"] > 0)
        return row if valid and bounds else None
    except (BadSignatureError, TypeError, ValueError, KeyError):
        return None


class Core:
    def __init__(self, resource_core, public_key, design, baseline, context):
        self.design = design
        self.key = VerifyKey(bytes.fromhex(public_key))
        self.resource_core = resource_core
        self.resource_state = resource_core.State()
        self.ipc = IPCState(public_key, design["deadline_ns"])
        self.previous = decode_resource(baseline, self.key, context, design) if context.seq == -1 else None
        self.run, self.episode = context.run, context.episode
        self.latest = -1
        self.streak = 0
        self.resource_confirmed = False

    def decide(self, envelope, ipc_envelope, context):
        if (context.run, context.episode) != (self.run, self.episode) or context.seq <= self.latest:
            return self.unknown("CONTEXT_REPLAY_OR_SUBSTITUTION", None)
        self.latest = context.seq
        ipc = self.ipc.step(ipc_envelope, context)
        row = decode_resource(envelope, self.key, context, self.design)
        previous = self.previous
        self.previous = row
        if not self.resource_continuity(previous, row):
            self.resource_state = self.resource_core.State()
            self.streak = 0
            self.resource_confirmed = False
            return self.unknown("RESOURCE_MISSING_UNTRUSTED_OR_DISCONTINUOUS", ipc)
        self.resource_state, resource = self.resource_core.decide(
            self.resource_state, signals(row, previous, self.design))
        if ipc["status"] == "UNKNOWN":
            self.streak = 0
            return self.unknown(ipc["reason"], ipc)

        # Count consecutive independently observed resource advisories.
        candidate = resource["action"] != "OBSERVE"
        self.streak = self.streak + 1 if candidate else 0
        confirmed = self.streak >= CONFIG["resource_confirmation_ticks"]
        resource_recovered = self.resource_confirmed and not candidate
        self.resource_confirmed = confirmed
        resource_status = ("RESOURCE_FAILURE" if confirmed else "RESOURCE_RECOVERY" if resource_recovered
                           else "RESOURCE_WARNING" if candidate else "NORMAL")
        ipc_status = "IPC_FAILURE" if ipc["alarm"] else "IPC_RECOVERY" if ipc["recovered"] else "NORMAL"
        incident = confirmed or ipc["alarm"]
        action = ("DEFER" if confirmed and resource["action"] == "DEFER" else "INVESTIGATE_CHANGE"
                  if incident else "OBSERVE")
        state = ("IPC_FAILURE" if ipc["alarm"] else "RESOURCE_FAILURE" if confirmed else
                 "RECOVERY" if ipc["recovered"] or resource_recovered else resource_status)
        return {
            "model_version": VERSION, "action": action, "state": state, "reason": None,
            "resource_status": resource_status, "ipc_status": ipc_status,
            "resource_streak": self.streak, "ipc": ipc,
        }

    def resource_continuity(self, previous, row):
        if previous is None or row is None or row["seq"] != previous["seq"]+1:
            return False
        elapsed = row["monotonic_ns"]-previous["monotonic_ns"]
        wall = row["utc_ns"]-previous["utc_ns"]
        return (0 < elapsed <= self.design["max_sample_interval_ns"] and wall > 0 and
                abs(wall-elapsed) < 50_000_000 and
                0 <= row["cpu_ns"]-previous["cpu_ns"] <= elapsed+32_000_000 and
                (row["disk_total_bytes"], row["disk_used_bytes"]) ==
                (previous["disk_total_bytes"], previous["disk_used_bytes"]))

    @staticmethod
    def unknown(reason, ipc):
        return {
            "model_version": VERSION, "action": "UNKNOWN/HOLD", "state": "UNKNOWN", "reason": reason,
            "resource_status": "UNKNOWN", "ipc_status": "UNKNOWN", "resource_streak": None, "ipc": ipc,
        }
