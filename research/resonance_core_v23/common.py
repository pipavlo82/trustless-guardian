import hashlib
import json
import math
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(Path(path).read_bytes())


def put(path, value):
    with Path(path).open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def put_lines(path, rows):
    with Path(path).open("xb") as stream:
        for row in rows:
            stream.write(canonical(row) + b"\n")


def _unique(pairs):
    value = {}
    for key, entry in pairs:
        if key in value:
            raise ValueError("DUPLICATE_JSON_KEY")
        value[key] = entry
    return value


def read_bytes(raw):
    value = json.loads(raw, object_pairs_hook=_unique)
    if raw != canonical(value) + b"\n":
        raise ValueError("NONCANONICAL_JSON")
    return value


def read(path):
    return read_bytes(Path(path).read_bytes())


def read_lines(path):
    with Path(path).open("rb") as stream:
        return [read_bytes(line) for line in stream]


def signals(row, previous, protocol):
    elapsed = row["monotonic_ns"] - previous["monotonic_ns"]
    cpu = (row["cpu_ns"] - previous["cpu_ns"]) / elapsed if elapsed else 0.0
    day = (row["utc_ns"] // 1_000_000_000) % 86400 / 86400
    lunar = ((row["utc_ns"] / 86_400_000_000_000) % 29.53059) / 29.53059
    solar = (math.sin(2 * math.pi * day) + 1) / 2
    return {
        "cpu": min(1.0, max(0.0, cpu)),
        "memory": min(1.0, row["rss_bytes"] / protocol["memory_envelope_bytes"]),
        "disk": row["disk_used_bytes"] / row["disk_total_bytes"],
        "hour_sin": solar,
        "hour_cos": (math.cos(2 * math.pi * day) + 1) / 2,
        "solar_proxy": solar,
        "lunar_proxy": (math.cos(2 * math.pi * lunar) + 1) / 2,
    }
