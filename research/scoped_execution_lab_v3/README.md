# Guardian + Resonance RC3 — research review branch

This branch preserves existing Guardian research history (PRs #1–8) and merges the already-merged PR #10, #11, and #12 research-branch changes. It includes a **new additive laboratory candidate** and the pinned Resonance Core V2.3; it does **not** promote either to production.

## Components

- `research/scoped_execution_lab_v1/` — frozen original scoped-execution laboratory, byte-preserved.
- `research/scoped_execution_lab_v3/` — candidate Windows AppContainer / authenticated broker / scoped grant / Docker worker / atomic signed receipt / unified SQLite WAL lifecycle.
- `research/resonance_core_v23/` — unmodified scientific source for deterministic resource/IPC advisories, supplied with portable dependency loaders.
- `tests/test_guardian_rc3_*.py` — synthetic lab unit tests.

The pinned lab worker is a disposable synthetic SHA-256 worker. Nothing here authorizes ordinary arbitrary tools, applications, credentials or production targets.

## Status / evidence limitations

Local Windows experiments confirmed bounded positive end-to-end execution and individual process-crash / receipt reconciliation scenarios. That is **research evidence, not production security approval**. The new RC3 review checkout needs its own test results; local historical trials are **not** fresh GitHub CI confirmations.

Known gaps: independent external anchor, coherent full-local-storage rollback, physical power-loss durability, independent second-machine validation, durable external protected effects, full production authorization and independent human security review. **PRODUCTION = HOLD**.

The actual science comparison of Core V2.3 was performed on one Windows machine with controlled injected failures. Its 48/48 detection and lower *incident-classified* false-alarm ticks were experiment-specific; benign resource warnings remained visible. Do not claim natural-fault prediction or scientific generality.

## Local checks

On Windows with Python 3.12 and required dependencies (`cryptography`, `PyNaCl`):

```powershell
python -B -m unittest discover -s tests -q
python -B -O -m unittest discover -s tests -q
python -B -m research.resonance_core_v23.SMOKE_REPLAY
```

**Windows Docker demo**, requiring the pinned Docker image and the supported AppContainer environment:

```powershell
python -B research/scoped_execution_lab_v3/guardian_rc2_adapter.py --out <new-unique-output-path> --intent research/scoped_execution_lab_v3/examples/intent-synthetic.json
```

The example intent is deliberately invented synthetic data; its hash is **not** independent proof of the source telemetry. Do not publish the generated run folder (contains ephemeral keys, Windows SID and unfiltered runtime evidence) without a privacy review.

Independent V3 verifier and reconciler are code-only under `research/scoped_execution_lab_v3/` and require real lab evidence to evaluate. Recovery never authorizes Docker create/start.

## Git history

Older PRs and their comments remain in GitHub history. This branch keeps their ancestors and does not rewrite or delete history. The original PR #8 CI workflow is retained; merged PR10–12 transition artifacts are preserved, but their original source-specific CI pin claims should not be reinterpreted as guarantees about this composite checkout.

A review PR may replace the old stacked Draft PRs as the single current **research** proposal after validation. No `main` merge or production promotion is implied.
