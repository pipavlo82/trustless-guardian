# Rare-event evidence v0 — synthetic research only

**Status: EXPERIMENTAL / TRIAGE_ONLY / HOLD.** This module is an optional, read-only research addition to `trustless-guardian` v0.7. It **never** approves, denies, retries, modifies policy, executes a tool, or changes the Windows AppContainer, broker, IPC, or journal. The `main` branch and existing Guardian Draft PR #1 are not part of this change.

## Why

Particle experiments distinguish a small candidate signal from a large background population. We borrow *only the methodology*: predeclared selection rules, a fixed baseline, separate signal and evidence layers, negative controls, and second-path recomputation. No physics discovery statistic, physical process, or claim about new particles transfers to the software.

## Data and detector

- Accepts **only explicitly synthetic** `guardian.rare-event.v0` JSONL, eight exact fields, contiguous `seq` starting at 1, no extras or unknown action/outcome, no filesystem paths used as execution targets. Maximum 20,000 records, 5 MB/file and 2,048 bytes/line. Minimum baseline 32 records. Source and baseline are untrusted unless independently authenticated elsewhere.
- Fixed action/outcome alphabet: 4 actions x 3 outcomes = 12 pairs. Count baseline frequencies, apply add-one smoothing, and flag a pair where `(count + 1) * 32 <= baseline_size + 12`. This *heuristic threshold is not a p-value*, confidence level, or calibrated false-positive guarantee.
- `DENIAL_BURST`: first crossing of four DENY outcomes in the last six events for one `(agent, resource)`.
- `DENY_ALLOW_REVISION_CHANGE`: an ALLOW after a recent DENY for the same `(agent, resource)`, with differing policy revision (last six related events). Legitimate policy changes can trigger it.
- `RECOVERY_OBSERVED`: any explicit `RECOVERY_REQUIRED` observation. It does not establish execution or non-execution.
- All findings are **triage candidates**, including ones correlated across time. No finding makes a claim of intrusion, misconduct, unauthorized execution, or proof.

The report binds the declared baseline and event arrays using deterministic SHA-256 of canonical sorted-key JSON. This detects accidental/stale mismatches **only when compared with separately held authoritative inputs**. Because there is no signature, authenticated acquisition, independent trust root, or append-only storage, an attacker able to rewrite *both* data and report can recompute the hashes. `RECOMPUTE_MATCH_UNAUTHENTICATED` must never be promoted to authorization.

## Run from repository root

Python 3.11+; standard library only.

```bash
python -m research.rare_event_evidence_v0.cli fixtures --out build/rare-events
python -m research.rare_event_evidence_v0.cli detect --baseline build/rare-events/baseline.jsonl --events build/rare-events/anomaly.jsonl --out build/rare-events/anomaly-report.json
python -m research.rare_event_evidence_v0.cli verify --baseline build/rare-events/baseline.jsonl --events build/rare-events/anomaly.jsonl --report build/rare-events/anomaly-report.json
python -B -m unittest discover -s tests -p test_rare_event_evidence_v0.py -v
```

Verify exits: `0` means recomputation matches **without source authentication**; `1` is `REFUTED` mismatch; `2` is malformed/out-of-scope input. No fallback to `PASS` on missing input. Only the `fixtures` command creates synthetic fixture files, and `detect` writes a report. `verify` is read-only.

## Observed local trial (2026-11-10, Python standard library)

- 27 unit tests: 27 PASS.
- 89 seeded generated synthetic streams (sizes 1–89): producer and second-path recompute matched in all 89. **Not independent language or host.**
- Curated benign holdout: 0 findings across 80 events. **Not a measured real-world false-positive rate.**
- Curated anomaly trace: 10 triage findings across 7 events; these include overlapping signals, **not 10 distinct attacks**.
- Physical input/report changes: changed baseline, changed event action, removed finding, changed finding kind, changed evidence reference, escalated report decision, reordered events, inserted event — all 8 tests refuted the unmodified report. Recalculated, maliciously forged input+report remains outside scope.

## Boundaries and next experiment

**No real production logs, private sandbox evidence or confidential H56/Q7 material.** No model/ML inference, OS-enforcement validation, end-to-end ReceiptOS/VECA integration, independent host replication, authenticated event provenance, attack attribution, calibrated alert thresholds, or production deployment. False positives and base-rate effects must be measured on a predeclared, permissioned held-out corpus before operational use. A later connector must be explicitly versioned and independently reviewed; do not feed `TRIAGE_ONLY` into security gates.

Current Guardian v0.7 is itself `HOLD` for production (hosted Windows limited-child startup not observed). This separate experiment does not lift that hold and must remain a Draft PR.
