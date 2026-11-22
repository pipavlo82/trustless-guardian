# Resonance original core + Trustless Guardian Windows IPC research v1

**Draft research candidate. No production or universal no-bypass claim.**

This is an *additive* reference integration, isolated in `research/resonance_guardian_v1/`. It does **not** replace Guardian Core. The included `reference_core/agent.py` is the original source snapshot from the author's Resonance Agent v1 project, with exact SHA-256:

`6bb44b71c62f54a3e1da2c11c73de5cf33766b8146c9c73f67711b9c07f0f1f6`

The source remains byte-identical. It is not a new inference engine: its `State/decide` logic processes bounded observations. This pilot executes that original logic inside a disposable Windows zero-capability AppContainer using a separately copied Python 3.12 runtime with only standard libraries. `psutil` is replaced by a **fail-closed import stub**, and no real sensors, Codex, MiroFish, persistent memory, background service or tools execute inside the confined process.

A distinct host broker creates a unique Windows named pipe. Its access-control list grants the particular AppContainer SID access, and the broker **impersonates the pipe client** and independently checks the AppContainer SID, zero capabilities, strict request schema and per-session nonce. The agent can request only `resonance.synthetic-hash-only.v0`; the broker **always returns HOLD_GUARDIAN_GRANT_REQUIRED**. No grant or Docker execution occurs.

## Independent populations

- **Portable**: 15 checks per mode, normal/repeat/optimized, including the exact source snapshot, bounded input rejection, deterministic decisions and failure of sensor access. Portable tests do NOT establish OS isolation.
- **Native Windows** (local evidence dated 2026-11-13): original AppContainer process 3-step run PASS; wrong nonce DENY, wrong tool DENY, ordinary host-client spoof DENY, no-broker fail-closed DENY. The confined client directly observed Win32 error 5 for two Docker pipes. Independent verifier rejected 16/16 in-memory evidence mutations per mode. Source-code physical mutations, multi-connection replay and third-party audit are NOT_COVERED.

To run portable tests from the repo root:

```text
python -B -m unittest discover -s research/resonance_guardian_v1/tests -q
python -B -m unittest discover -s research/resonance_guardian_v1/tests -q
python -B -O -m unittest discover -s research/resonance_guardian_v1/tests -q
```

Native Windows pilot (requires 64-bit Python 3.12, non-elevated local Windows with AppContainer support; runs **no Docker commands**):

```text
python -B research/resonance_guardian_v1/native_assessment.py --strict --out build/resonance-ipc-native-review
```

The `--out` directory must be new. CI without physical AppContainer support emits `NOT_COVERED`, never asserts VERIFIED. Follow `SECURITY_REPORT.md` for risk and `REPLAY.md` for replay commands.

## Scope and licensing

This project is Apache-2.0. The snapshot is code from the same author's own local Resonance research, deliberately included for this explicit public research PR. No third-party MiroFish/AGPL code, private project data, credentials, saved observations, personal machine paths, raw organizational evidence, or Codex conversations are bundled.

**Production HOLD. Do not merge until independent security review.**
