# Prioritized defect register

| ID | Priority | Evidence | Defect | Disposition |
|---|---:|---|---|---|
| SG-001 | Critical for the synthetic oracle | Independently reproduced | v0 allowed admin, owner/resource, and service requests without binding the acting principal to the asserted wallet/resource/service. | Fixed additively in v1; four exact reproducers retained. No live-production bypass is claimed. |
| SG-002 | High | Independently reproduced | Legacy integrity rejected all 26 PR #2/#3 additions as unlisted, so fresh PR #3 portable CI failed despite passing synthetic jobs. | Fixed with pinned frozen and repair layers; original manifest and all 210 digests preserved. |
| SG-003 | High / release blocker | Upstream hosted artifact plus local independent assessment | Hosted reduced-token processes are created and resumed but never execute user code; local non-elevated caller cannot exercise that reduction path. | Open. Hosted symptom classified, internal Windows cause unestablished. Windows gate remains failing and verdict remains `HOLD`. |
| SG-004 | High for the synthetic oracle | Independently reproduced | v0 public `HEALTH` allowed unsafe payload shape. | Fixed by exact public-health shape in v1. |
| SG-005 | Medium | Independently recomputed | v0 detector missed subject, wallet, resource, and cross-service binding attacks and flagged legitimate short administrative bursts. | Fixed on a separate v1 synthetic held-out set; real-world accuracy remains `NOT_COVERED`. |
| SG-006 | Medium | Source review | v0 held-out attacks were transformations of the attack fixture, weakening independence. | v1 held-out construction is separate from the functional trace and includes legitimate admin/owner/service activity. |
| SG-007 | Medium | Source review and mutation runs | v0 mutations exercised input/report recomputation but not physical policy/detector source changes. | Added 16 physical source mutants with per-mutant fresh baseline and restored control. |
| SG-008 | Medium | Independent mutation calibration | Initial source-mutant designs contained two semantically redundant role-check removals; replacement cross-service mutants then survived because regression tests lacked those exact negative controls. | Mutants corrected, two negative controls added, final result 16/16 killed. Failed calibration runs remain disclosed. |
| SG-009 | Medium | Source review | PR #2/#3 workflows use floating action major tags, expanding supply-chain mutability. | Historical workflows remain frozen. New repair workflow pins action commit SHAs and disables persisted checkout credentials. Action provenance itself is not proven. |
| SG-010 | High for evidence claims | Source review | Synthetic report recomputation is deterministic but unauthenticated; fixture booleans are not JWT, wallet, registry, or external-effect proof. | Explicitly retained as `RECOMPUTE_MATCH_UNAUTHENTICATED`; production authentication and provenance remain open. |
| SG-011 | High for Linux production use | Independent local pilot | Rootless daemon mode, production bearer validation, real tool integration, and production egress policy were not exercised. | Local synthetic pilot only; production gate remains open. |
| SG-012 | Medium | Source and CI review | A hosted runner is not an independent second machine and existing PR #3 Guardian jobs fail before full closure. | New workflow recomputes portable evidence and preserves the Windows failure as a gate; external review still required. |

## Reproducers

```text
python -B tools/audit_v0_bindings.py --out build/gateway-v1/v0-binding-audit.json
python -B -m research.gateway_abuse_replay_v0.cli evaluate --out build/gateway-v1/v0-metrics.json
python -B -m research.gateway_abuse_replay_v1.cli evaluate --out build/gateway-v1/v1-metrics.json
python -B tools/source_mutations_v1.py --out build/source-mutations-v1/report.json
```

The v0 metrics (`52/6/276/18`) and v1 metrics are from different corpora and must not be presented as a direct before/after statistical comparison. The v1 report separately computes a v0 projection over the same v1 held-out corpus for the bounded comparison.
