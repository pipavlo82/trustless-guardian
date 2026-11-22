"""Resonance Core V2: bounded online change detector.

This is a research model, not a physical law.  It consumes the same normalized
seven-channel schema as Core V1 but makes decisions only from the three measured
operational channels.  Time/solar/lunar proxy fields are validated and retained
for schema compatibility; they are not treated as causal failure signals.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import math


MODEL_VERSION = "resonance-core-v2.0-rc2"
FIELDS = ("cpu", "memory", "disk", "hour_sin", "hour_cos", "solar_proxy", "lunar_proxy")
OPERATIONAL_FIELDS = ("cpu", "memory", "disk")
WEIGHTS = {"cpu": 0.45, "memory": 0.35, "disk": 0.20}


@dataclass(frozen=True)
class Config:
    warmup_steps: int = 8
    baseline_alpha: float = 0.04
    variance_floor: float = 0.0004
    initial_variance: float = 0.0025
    score_decay: float = 0.55
    entry_threshold: float = 2.40
    exit_threshold: float = 1.10
    persistence_steps: int = 2
    recovery_steps: int = 3
    baseline_update_gate: float = 1.60
    pressure_entry: float = 0.93
    pressure_exit: float = 0.78
    z_cap: float = 8.0
    memory_length: int = 32


CONFIG = Config()


@dataclass
class State:
    step: int = 0
    means: dict[str, float] = field(default_factory=dict)
    variances: dict[str, float] = field(default_factory=dict)
    sequential_score: float = 0.0
    excursion_count: int = 0
    recovery_count: int = 0
    alarm: bool = False
    previous_signals: dict[str, float] | None = None
    score_memory: list[float] = field(default_factory=list)


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def config_dict() -> dict:
    return asdict(CONFIG)


def config_sha256() -> str:
    return hashlib.sha256(canonical(config_dict())).hexdigest()


def _validate(signals: dict) -> None:
    if type(signals) is not dict or set(signals) != set(FIELDS):
        raise ValueError("CORE_V2_SIGNAL_SCHEMA")
    for value in signals.values():
        if type(value) not in (int, float) or not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise ValueError("CORE_V2_SIGNAL_DOMAIN")


def _baseline_update(state: State, values: dict[str, float], alpha: float) -> None:
    for name in OPERATIONAL_FIELDS:
        old_mean = state.means[name]
        delta = values[name] - old_mean
        new_mean = old_mean + alpha * delta
        # EW variance uses the old-to-new residual product.  The explicit floor
        # prevents a constant warm-up trace from making later tiny noise infinite.
        updated = (1.0 - alpha) * state.variances[name] + alpha * delta * (values[name] - new_mean)
        state.means[name] = new_mean
        state.variances[name] = max(CONFIG.variance_floor, updated)


def decide(state: State, signals: dict) -> tuple[State, dict]:
    """Advance one state and return a deterministic advisory decision.

    The score is a clipped weighted Mahalanobis-like diagonal residual, followed
    by an EW sequential filter.  Persistence and hysteretic recovery are explicit
    engineering choices intended to suppress one-tick noise; they are not proofs
    about the monitored system.
    """
    _validate(signals)
    values = {name: float(signals[name]) for name in OPERATIONAL_FIELDS}
    if state.step == 0:
        state.means = dict(values)
        state.variances = {name: CONFIG.initial_variance for name in OPERATIONAL_FIELDS}

    z = {}
    for name in OPERATIONAL_FIELDS:
        scale = math.sqrt(max(CONFIG.variance_floor, state.variances[name]))
        z[name] = min(CONFIG.z_cap, abs(values[name] - state.means[name]) / scale)
    raw_score = math.sqrt(sum(WEIGHTS[name] * z[name] * z[name] for name in OPERATIONAL_FIELDS))
    sequential = CONFIG.score_decay * state.sequential_score + (1.0 - CONFIG.score_decay) * raw_score
    pressure = 0.50 * values["cpu"] + 0.30 * values["memory"] + 0.20 * values["disk"]

    warmup = state.step < CONFIG.warmup_steps
    if warmup:
        alpha = 1.0 / float(state.step + 2)
        _baseline_update(state, values, alpha)
        state.excursion_count = 0
        state.recovery_count = 0
        state.alarm = False
    else:
        elevated = sequential >= CONFIG.entry_threshold or pressure >= CONFIG.pressure_entry
        state.excursion_count = state.excursion_count + 1 if elevated else 0
        if not state.alarm and state.excursion_count >= CONFIG.persistence_steps:
            state.alarm = True
            state.recovery_count = 0
        if state.alarm:
            calm = sequential <= CONFIG.exit_threshold and pressure <= CONFIG.pressure_exit
            state.recovery_count = state.recovery_count + 1 if calm else 0
            if state.recovery_count >= CONFIG.recovery_steps:
                state.alarm = False
                state.excursion_count = 0
                state.recovery_count = 0
        if not state.alarm and raw_score < CONFIG.baseline_update_gate:
            _baseline_update(state, values, CONFIG.baseline_alpha)

    if state.alarm and pressure >= CONFIG.pressure_entry:
        action = "DEFER"
    elif state.alarm:
        action = "INVESTIGATE_CHANGE"
    else:
        action = "OBSERVE"

    state.step += 1
    state.sequential_score = sequential
    state.previous_signals = dict(signals)
    state.score_memory.append(round(sequential, 8))
    if len(state.score_memory) > CONFIG.memory_length:
        del state.score_memory[:-CONFIG.memory_length]
    decision = {
        "schema": "resonance.core-v2.decision.v1",
        "model_version": MODEL_VERSION,
        "config_sha256": config_sha256(),
        "step": state.step,
        "action": action,
        "alarm": state.alarm,
        "warmup": warmup,
        "raw_score": round(raw_score, 8),
        "sequential_score": round(sequential, 8),
        "pressure": round(pressure, 8),
        "excursion_count": state.excursion_count,
        "recovery_count": state.recovery_count,
    }
    return state, decision


def state_dict(state: State) -> dict:
    return asdict(state)

