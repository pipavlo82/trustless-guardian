# Replay — PR #7 Resonance AppContainer IPC

All commands are from the repository root. Pin the exact reviewed commit. Do not run as Administrator to bypass failures. No pip dependencies are needed for the standalone portable/Windows pilot.

## Portable

```text
python -B -m unittest discover -s research/resonance_guardian_v1/tests -q
python -B -m unittest discover -s research/resonance_guardian_v1/tests -q
python -B -O -m unittest discover -s research/resonance_guardian_v1/tests -q
```

## Native Windows, new output path per run

```text
python -B research/resonance_guardian_v1/native_assessment.py --strict --out build/resonance-ipc-v1/native
```

Expected case paths under output: `evidence_normal.json`, `evidence_bad_nonce.json`, `evidence_bad_tool.json`, `host_spoof_result.json`, `outage_result.json`, and `verification_{normal,repeat,optimized}.json`.

The native assessment executes only a small bounded zero-capability AppContainer and a fixed synthetic host broker. It does not issue actual Guardian grants, execute Codex, Docker or MiroFish, or access production data.

If no native Windows AppContainer execution is available, `assessment.json` must say `NOT_COVERED` and preserve the error. Never replace this with a mocked PASS.

## Integrity

Run `tools/integrity_v4.py` with the **externally pinned v4 policy SHA-256 from the candidate workflow**, then `tools/integrity_mutations_v4.py`. Every successful mutation experiment must preserve the baseline, produce a rejecting mutant and restore the file before re-verifying.

## Rules

Prior PR #1–#6, main, history and evidence are unchanged. PR #7 is Draft, independent review required. Production HOLD.
