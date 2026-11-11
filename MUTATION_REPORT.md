# Mutation report

Mutation statuses are exclusive: `KILLED`, `SURVIVED`, `NOT_APPLIED`, `CRASHED`, and `CONTROL_BROKEN`. A mutation is `KILLED` only when its fresh baseline passes, the exact mutation is applied, the security test rejects it, original bytes are restored, and the restored control passes.

## Final repair populations

| Population | KILLED | SURVIVED | NOT_APPLIED | CRASHED | CONTROL_BROKEN |
|---|---:|---:|---:|---:|---:|
| Gateway v1 input/report mutations | 15 | 0 | 0 | 0 | 0 |
| Gateway v1 physical source mutations | 16 | 0 | 0 | 0 | 0 |
| Layered-integrity physical mutations | 11 | 0 | 0 | 0 | 0 |
| **Repair total** | **42** | **0** | **0** | **0** | **0** |

The source-mutation report SHA-256 is `606af43ac66b186c9e97acba9ff2ea6ffce16fe890b5f8bd5a2bb9bd4f3aebf4`.

## Non-final runs retained

The first source campaign returned 14 killed and 2 survived. Those two role-removal mutants were semantically redundant because the strict subject/wallet registry already determined the role for the tested identity. They were removed from the population rather than mislabeled as killed.

The next campaign again returned 14 killed and 2 survived after replacing them with admin-service and tool-service boundary mutations. This exposed missing explicit negative controls. The two controls were added; the unchanged meaningful mutants were rerun and killed. Both failed campaigns are part of the audit history and are not counted as final PASS results.

The first Linux pilot returned `HOLD` because the observer assumed cgroup v2 paths while the available Docker Desktop engine exposed cgroup v1. That result was not relabeled. The observer was corrected and the full positive, negative, limit, network, and recovery controls were rerun.

The first layered-integrity baseline returned `invalid base commit`: the verifier incorrectly applied a 64-hex SHA-256 predicate to the repository's 40-hex Git object ID. No PASS was claimed. The Git-object predicate was corrected, manifests and the independent policy pin were recomputed, and only then were the passing baseline and 11 physical mutations executed.

The first source-mutation run from the fresh clone returned `CONTROL_BROKEN=16`: after the v0 defect reproducer became a test dependency, the disposable mutation tree copied `research/` and the test file but omitted `tools/audit_v0_bindings.py`. The harness was fixed to copy that dependency; no broken-control case was counted as killed, and the full population was rerun from the fresh clone.

## Historical mutation truth

The repair does not rewrite historical results. PR #1 continues to report `IMMUTABLE_V06_2_KILLED_2_CONTROL_BROKEN`, and older v0.3 evidence includes its recorded survivor. A passing new repair population cannot erase those frozen outcomes.

The PR #3 v0 input/report audit independently recomputes 13 `KILLED_REFUTED`, 1 `KILLED_INPUT_REJECTED`, and no survivor, but it is not a physical source-mutation population and is not merged into the 42 repair total.
