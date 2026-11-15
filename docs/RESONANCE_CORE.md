# 🧠 Resonance Core — what it is, and what it is not

> **Research component · deterministic decisions · proposal-only Guardian integration · production HOLD**

[← Back to Guardian](../README.md) · [Original PR #7](https://github.com/pipavlo82/trustless-guardian/pull/7) · [Mutual IPC successor PR #8](https://github.com/pipavlo82/trustless-guardian/pull/8)

## In plain language

Resonance Core is a small **stateful signal-processing and decision engine** written in Python.

It receives numerical observations, remembers a compact previous state, calculates how much the inputs changed and how high the load is, then emits a deterministic action label. It is **not a large language model**, does not converse, and does not know a person's private intention.

Think of it as an **experimental observation-and-decision kernel**, not a human mind or an autonomous operator.

The original source is included byte-for-byte at:

[<code>research/resonance_guardian_v1/reference_core/agent.py</code>](https://github.com/pipavlo82/trustless-guardian/blob/2a40075a7f217e9c385cdfaf27c0267fa788d574/research/resonance_guardian_v1/reference_core/agent.py)

SHA-256 of that original file:

<code>6bb44b71c62f54a3e1da2c11c73de5cf33766b8146c9c73f67711b9c07f0f1f6</code>

This is a preserved source snapshot from the author's Resonance research, not a rewrite of the Guardian enforcement core.

## The seven input channels

Every accepted input is a finite number between 0 and 1. The set of fields must match **exactly**, with no missing or additional fields.

| Channel | Interpretation |
| :--- | :--- |
| <code>cpu</code> | Normalized CPU utilization |
| <code>memory</code> | Normalized memory usage |
| <code>disk</code> | Normalized disk usage |
| <code>hour_sin</code> | Sine-based time-of-day feature |
| <code>hour_cos</code> | Cosine-based time-of-day feature |
| <code>solar_proxy</code> | Illustrative time phase, not measured solar activity |
| <code>lunar_proxy</code> | Illustrative phase proxy, not a verified lunar ephemeris |

In the standalone original implementation, <code>measure()</code> can query local utilization via <code>psutil</code> and compute the time features. **In the Guardian AppContainer experiment, real sensor access is disabled**, <code>psutil</code> is stubbed to fail closed, and the broker supplies only bounded synthetic values.

## Internal state and transition

The source defines an internal <code>State</code> with:

- <code>step</code>: a sequence counter;
- <code>attention</code>: a numeric state variable updated by a weighted change signal;
- <code>energy</code>: a numeric state variable updated by load pressure;
- <code>phase</code>: an evolving mathematical angle;
- <code>previous_signals</code> and <code>previous_hash</code>: compact history references.

The transition computes:

- **Novelty:** a weighted sum of the absolute differences between the current and previous seven observations;
- **Pressure:** <code>0.5 × cpu + 0.3 × memory + 0.2 × disk</code>;
- **Attention, energy and phase:** deterministic updates of the previous numeric state.

The current action rule is evaluated in order:

| Condition | Decision |
| :--- | :--- |
| <code>pressure > 0.88</code> | <code>DEFER</code> |
| Otherwise, <code>novelty > 0.20</code> | <code>INVESTIGATE_CHANGE</code> |
| Otherwise, <code>attention > 0.60</code> | <code>REVIEW</code> |
| Otherwise | <code>OBSERVE</code> |

**Important:** <code>attention</code> and <code>energy</code> are engineering names for numbers, **not evidence of subjective awareness or feelings**. The current <code>energy</code> and <code>phase</code> values are retained as state but do not directly grant tool permissions or override the action thresholds.

The original standalone script can emit SHA-256-linked JSONL records. Hash chaining helps detect inconsistent modifications to that record sequence; it does not establish independently trusted timestamps, authentic sensor provenance or remote process identity.

## 🔒 How Guardian confines the experiment

[Draft PR #7](https://github.com/pipavlo82/trustless-guardian/pull/7) embeds the original <code>State/decide</code> logic into a disposable Windows zero-capability AppContainer. The broker checks the client AppContainer SID and available capabilities, and the valid test request ends in **<code>HOLD_GUARDIAN_GRANT_REQUIRED</code>**. Direct access to the two tested Docker named-pipe endpoints was denied in local native observations.

[Draft PR #8](https://github.com/pipavlo82/trustless-guardian/pull/8) adds **mutual IPC research**: broker responses are signed with a pinned Ed25519 public key, bound to session, challenge, channel, phase, request hash, expected broker/key identity and a short validity window. Bounded Windows named-pipe I/O and an offline evidence verifier are also tested.

The three synthetic signal steps in the valid path are 0.20 → 0.30 → 0.40, resulting in <code>OBSERVE</code>. The client proposes a synthetic hash-only tool label; the Guardian broker **does not execute it**.

~~~mermaid
sequenceDiagram
    participant S as Synthetic signal source
    participant R as Resonance (AppContainer)
    participant B as Guardian broker
    S->>B: bounded synthetic observations
    R->>B: HELLO + session challenge
    B-->>R: signed synthetic observations
    R->>R: State / decide
    R->>B: bound proposal (OBSERVE)
    B-->>R: signed HOLD_GUARDIAN_GRANT_REQUIRED
    Note over R,B: No grant, worker or production tool execution
~~~

The PINNED broker key proves a signature under that key; it does **not** independently prove the broker executable's OS identity. Local Windows evidence is not a third-party attestation. Current production key custody, revocation distribution and rollback resistance remain unestablished.

## 🧪 What tests establish

- Exact original source hash pin and deterministic input/decision tests.
- Strict refusal of malformed schema and non-finite or out-of-range observations.
- Real bounded Windows AppContainer research runs on local synthetic evidence.
- Signed IPC / incorrect-key / wrong-request / timeout negative cases in PR #8.
- Offline recomputation and mutation witnesses, with explicit preservation of failures and unsupported coverage.

The [PR #8 description](https://github.com/pipavlo82/trustless-guardian/pull/8) gives exact commits, local evidence populations and reproduction instructions. **Green hosted CI does not imply full native OS enforcement or production authorization.**

## 🌱 What is next — not implemented here

Possible future experiments include comparing deterministic anomaly flags with independent semantic consistency checks, testing false alarms and studying differences between human and AI decisions. None is an existing Resonance Core feature, and no present result establishes human fatigue recognition or human-intent inference.

Any future integration should preserve these boundaries:

1. A signal may **suggest closer inspection**, but may not grant or override authorization.
2. A pause should have a precise, independently checkable reason wherever a checkable rule exists.
3. A missing proof stays **NOT_ESTABLISHED**; a failed check can be **REFUTED**.
4. Experimental work must not silently enable tool execution or change the original core.

**Bottom line:** Resonance is a measurable, reproducible decision experiment. Guardian is the separately controlled security boundary. The combination is promising research, **not a production-certified autonomous AI system**.
