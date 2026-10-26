# Developer preview

See [prerequisites and troubleshooting](../../docs/DEVELOPER_PREVIEW.md).
After `python -B tools/prepare.py`, choose one explicit population:

```powershell
python -B demo/developer-preview/run.py --mode deterministic --out build/offline-demo
python -B demo/developer-preview/run.py --mode live --runtime build/guardian-lab-hermes-runtime --out build/live-demo
```

Only the second invokes a real model. It requires the pinned prepared Hermes
runtime and existing host Codex authentication. Neither falls back to the other.
Both use newly provisioned synthetic Windows resources.

```powershell
python -B demo/developer-preview/mutations.py --out build/deterministic-mutations
python -B demo/developer-preview/verify.py build/live-demo/observations.json --out build/live-demo/reverified.json
```

vectors.json is synthetic input frozen by SHA-256 in runner and independent oracle;
never a live model response. Physical edits affect only copied lab files. Healthy
before/restored controls and independently observed unsafe behavior are mandatory.
