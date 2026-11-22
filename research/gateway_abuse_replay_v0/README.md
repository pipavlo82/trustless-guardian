# Gateway Abuse Replay v0 — synthetic security experiment

**EXPERIMENTAL / HOLD. No organization-specific logs, real endpoints, wallet addresses, keys, command strings, or incident evidence are included.** This is a *fictionalized attack-class test*, not a factual reconstruction of an organization-specific incident. No live network calls, containers, authentication requests, or production policy changes occur.

This is a stacked research addition to `trustless-guardian` Draft PR #2. Only new files are added; **Guardian v0.7 core, broker, policies, historical evidence and `main` are unchanged**. Parent v0.7/PR #1 and PR #2 remain on HOLD.

## Contract and method

- Input is a fixed-schema, exact-field synthetic JSONL envelope with sequence numbers and synthetic integer ticks (not real timestamps). Only enum-based synthetic wallets, services, payload classes, and principals are accepted. 2,000-event/1 MB limits. Missing or duplicate fields, unrecognized operations, invalid claims, bad ordering and oversized inputs are rejected before any report is generated.
- A **separate policy-simulation path** checks token-verification assumptions, admin role plus wallet binding, owner registration plus independently asserted registry ownership, approved destinations, allowlisted tool classes, and service-specific identities. `DENY` is **not an observed enforcement action**. `token_verified` and `ownership_proof` in synthetic fixtures are fabricated truth values, **not actual JWT verification or live on-chain proofs**. A real implementation must obtain these facts from authenticated independent sources.
- A **triage-only path** flags activity bursts, wrong role at admin operations, unbound registrations, unusual MCP destinations, high-risk command classes and cross-service sequences. It cannot grant permissions and is not a confidence score, p-value, or proof of intrusion.
- Inputs are also projected into `rare_event_evidence_v0`; this projection is versioned, excludes `NOT_COVERED` events instead of treating unknown outcomes as ALLOW, and keeps `TRIAGE_ONLY`. It is not independent authorization evidence.
- The second-path verifier recomputes policy conditions using a separate declarative oracle, walks the detection stream using a different algorithm, independently reconstructs the full report and runs the prior rare-event v0 reference recomputation. It *shares* schema, canonicalization, digest primitives and the legacy adapter. It does **not** supply independent host, source, cryptographic authenticity, or implementation governance.

## Four classification labels

| Label | Precise meaning in this experiment |
| --- | --- |
| `BLOCKED_BY_AUTHORIZATION` | The *simulated* policy returns DENY. **Not** an observed system call / real gateway refusal. |
| `DETECTED_ONLY` | Simulated policy ALLOW, but at least one triage signal fired. No preventive mechanism demonstrated. |
| `NOT_DETECTED` | Simulated policy ALLOW and detector has no signal; may be benign or missed adversarial intent. |
| `NOT_COVERED` | External effect cannot be independently observed by the offline harness. Never map to ALLOW. |

## Reproducible synthetic timeline

The constructed trace has 14 events, of which 12 are separately annotated as adversarial. It intentionally includes benign-looking actions, and it is **not** a minute-by-minute incident transcript:

| Synthetic event | Attempted behavior | Recorded outcome |
| --- | --- | --- |
| 1 | Public health | `NOT_DETECTED` (public read) |
| 2–3 | Owner-scope skill tests | ALLOW, no signal; illustrates possible early false negatives |
| **4** | Third rapid owner-scope test | **First `ACTIVITY_BURST` detection**, `DETECTED_ONLY` |
| **5** | Signed owner-scope JWT submitted to admin operation | **First simulated `DENY`**, `ADMIN_WALLET_ROLE_REQUIRED` |
| 6 | Agent registration lacking independently asserted ownership proof | DENY, `REGISTRY_PROOF_REQUIRED` |
| 7–8 | Admin-only skill/MCP changes, unapproved target | DENY; triage signals |
| 9 | Allowed owner-scope tool test | ALLOW, no signal |
| 10 | External MCP call without service identity | DENY, cross-service triage |
| 11 | Unsafe tool-runner payload class | DENY, no shell execution |
| 12 | Cross-service messaging call without scoped identity | DENY, cross-service triage |
| 13 | Unknown external result | `NOT_COVERED`, no claim of exfiltration |
| 14 | Public health | ALLOW |

**First detection: event 4. First simulated prevention: event 5.** There is **no demonstrated actual prevention** and no measured real-world detection latency. Seven operations in the single attack trace receive simulated DENY; this does not certify a Linux gateway or Windows AppContainer.

## Run (from repository root)

Python 3.11+ standard library. Output paths below are untrusted, newly created scratch artifacts under `build/`.

```bash
python -B -m research.gateway_abuse_replay_v0.cli fixtures --out build/gateway-replay
python -B -m research.gateway_abuse_replay_v0.cli run --events build/gateway-replay/attack.synthetic.jsonl --out build/gateway-replay/attack.report.json
python -B -m research.gateway_abuse_replay_v0.cli verify --events build/gateway-replay/attack.synthetic.jsonl --report build/gateway-replay/attack.report.json
python -B -m research.gateway_abuse_replay_v0.cli evaluate --out build/gateway-replay/holdout.json
python -B -m research.gateway_abuse_replay_v0.cli mutations --out build/gateway-replay/mutations.json
python -B -m unittest discover -s tests -p test_gateway_abuse_replay_v0.py -v
python -B -O -m unittest discover -s tests -p test_gateway_abuse_replay_v0.py -q
```

CLI exit codes: `0` means successful **synthetic** computation or matching unauthenticated recomputation; `1` means report mismatch or mutation campaign failures; `2` means invalid/missing input. **`0` never means real-world authorization, authenticity or production readiness.** The read-only verifier never executes any event.

## Held-out measurement (deterministic but NOT representative)

Six benign streams include one *legitimate* rapid burst each, ensuring false positives are visible. Six altered attack streams include indistinguishable early owner-level tests, ensuring false negatives are visible. Ground-truth labels are separate from event records and are never inspected by the detector.

- Total 352 synthetic events. Event-level TP = **52**, FP = **6**, TN = **276**, FN = **18**.
- Observed synthetic FPR = **6/282 (~2.13%)**; FNR = **18/70 (~25.71%)**. No sampling confidence, calibration or generalization to live traffic.
- Simulated DENY on 42 adversarial events across held-out streams, but these are *counterfactual policy decisions*, not successful enforcement of real actions.
- 14 physical input/report mutations: **13 REFUTED** and **1 rejected as invalid input**, **0 SURVIVED / NOT_APPLIED / CONTROL_BROKEN**. Mutations have original/mutated digests and byte-exact restoration in a disposable directory. They do not detect coordinated forged input-plus-report with a recomputed digest.
- `SYNTHETIC_EVIDENCE.json` stores a deterministic, machine-readable attack report, labelled holdout metrics and mutation-control inventory. The regression test recomputes and matches the exact bytes.

## Security boundaries, remaining gaps and review gates

1. **Authentication and trusted root not proven.** JWT validity, admin-wallet membership, agent ownership at a pinned chain block, signed service identity, session context and log provenance require independent verification. The model trusts synthetic booleans that a real gateway must not take from an untrusted client or log.
2. **Enforcement not observed.** No Linux sidecar, `--network none`, seccomp, user namespaces, filesystem confinement, process restrictions or real MCP ingress authentication was tested. No permission to restart, connect to or execute tools on any real gateway is implied. A policy emulator can say DENY while an actual gateway still executes the request.
3. **Detection is heuristic, not causality or attribution.** Legitimate automation triggers false alerts; silent abuse or sequence camouflage can escape it. No adaptive ML, calibrated threshold, sampling plan or threat-actor identification.
4. **Provenance remains unauthenticated.** SHA-256 binds the report to a *provided* event stream; modifying both events and report can still produce a matching digest. No independent signed root, append-only anchor, complete forensic acquisition, SIEM or ReceiptOS/VECA chain.
5. **Upstream frozen inventory conflict.** Existing `tools/integrity.py` tracks an exact historical file inventory. New additions produce `unlisted` under legacy tests, even when old bytes are unchanged. **Do not relax the check or rewrite historical manifests.** Versioned additive inventory and independent review are needed before integration.
6. **Reproducibility and review.** Synthetic CI runs normal/repeated/optimized Python on Ubuntu and Windows; neither CI run is OS-enforcement evidence. Preserve all failure logs and keep Draft/HOLD. Before anything operational, obtain explicit organization approval and a private, authorized replay of separately collected, verified logs.

Decision: **EXPERIMENTAL / HOLD** for merger, deployment, breach attribution, prevention claims and security certification. Gates, not scores. Don't trust; recompute.
