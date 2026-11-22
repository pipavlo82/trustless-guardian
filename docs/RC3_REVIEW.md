# Guardian + Resonance RC3 — Release Candidate Review (research)

## History preserved

This candidate branches from Guardian PR #8's frozen research head and includes explicit merge ancestry from the already merged PR #10, #11 and #12 successors. No remote history or old pull request has been deleted or force-pushed. Merge conflicts in the legacy CI transition files were resolved by keeping the PR #8 workflow and the most recent source-bound PR #12 transition variant; older versions remain accessible through their merge parents. The original PR10/11/12 artifacts are not automatically claims about RC3.

## What is runnable

- The additive `research/scoped_execution_lab_v3/` candidate contains the authenticated Windows AppContainer broker, scoped Ed25519 execution grant, restricted synthetic Docker worker, verified worker readback, atomic signed receipt, and unified SQLite WAL admission/execution lifecycle.
- `research/resonance_core_v23/core_v2_3.py` retains its original SHA-256 source bytes. This is the experimental deterministic advisory model, not a new mathematical V3 or a production authorizer.
- A public synthetic intent fixture, portable tests, and code-only independent verifier/reconciler are included. **No local crash evidence directories, raw logs, ephemeral private keys or runtime security identities are included in this branch.**

## Fresh checkout-level validation on Windows, 2026-11-22

- 201 unit tests PASS in normal and 201 PASS in Python `-O` mode.
- The Core V2.3 import/source-pin smoke test PASS.
- One **fresh, real** Windows AppContainer → authenticated Guardian broker → scoped grant → isolated Docker worker → atomic receipt → SQLite COMMITTED path PASS for a synthetic request, with exactly one authorized worker launch.
- Four actual refusals (replay grant, request substitution, missing grant, revoked policy) generated no extra Docker launches.
- The independent verifier returned `LOCAL_CONFIRMED_EXTERNAL_HOLD`, with the bounded worker/result identity verified. This is not a remote-anchor verdict.
- Fresh end-to-end runtime evidence was inspected locally but **not published** due to private runtime metadata.

Previously recorded V3 crash-window and reconciliation results remain local to the author's machine. They have **not** been independently replayed on this composite RC3 checkout; the combined branch is a review candidate, not a promoted security release.

## Known limitations / nonclaims

`PRODUCTION = HOLD`. External anchor and independent organization authentication are absent. Coherent rollback of all same-host files remains undetectable without external trust. Full power-loss durability, second-machine reproducibility, real-world protected effects, natural failure prediction, and independent human security review are not established.

The execution tools are fixed synthetic-hash-only. No fallback around Guardian authorization, no arbitrary command executor, no production credentials, no deployment.

## Local reproduction (research only)

Use Windows Python 3.12 with required cryptography + PyNaCl packages; pinned Guardian runtime dependencies, Docker Linux Engine and the lab image are prerequisites for full E2E:

```powershell
python -B -m unittest discover -s tests -q
python -B -O -m unittest discover -s tests -q
python -B -m research.resonance_core_v23.SMOKE_REPLAY
python -B research/scoped_execution_lab_v3/guardian_rc2_adapter.py --out <new-unique-folder> --intent research/scoped_execution_lab_v3/examples/intent-synthetic.json
python -B research/scoped_execution_lab_v3/verify_unified_independent.py <new-unique-folder>
```

`<new-unique-folder>` is intentionally outside the Git repository and must not be committed; it contains local runtime evidence and signing metadata. The example intent is synthetic and does not verify actual telemetry provenance.

This is a single-review-branch consolidation of historical work for technical collaboration, not a rights transfer or production acceptance.
