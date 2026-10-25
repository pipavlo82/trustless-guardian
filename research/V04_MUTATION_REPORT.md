# v0.4 physical mutation population

Initial actual result: **5 KILLED / 0 SURVIVED / 0 CRASHED / 0 NOT_APPLIED /
0 CONTROL_BROKEN**. Exact source replacements and original/changed/restored SHA-256
are recorded. Each original/restored case has a permitted positive control and
real host snapshots; a crash or missing observation cannot count as KILLED.

| ID | Changed boundary | Distinguishing witness / scope |
| --- | --- | --- |
| ordinary_exception_legacy | Restore selective exception tuple | Real write + RuntimeError via preserved legacy server path gives false NOT_EXECUTED. New dispatcher is deliberately outside this isolated legacy contract; combined dispatch may provide additional protection |
| recovery_response | Label recovery-gate response NOT_EXECUTED | Same nonce after real write/process termination; durable ambiguous state must remain ambiguous |
| dispatch_outcome | Label unexpected backend exception NOT_EXECUTED | Real commit followed by wrapper exception; fallback cannot prove non-execution |
| readback_consistency | Remove exact post-write readback comparison | Actual wrong bytes are otherwise committed; fault is a trusted lab hook, not an agent authorization bypass |
| same_identity_pipe_level | Remove explicit effective-level check | Actual same-AppContainer pipe token levels2/3 incorrectly accepted; no protected resource authority is exercised |

These five are a new population. Do not add them to historical15/11/3+1 as though
they were one experiment. v03's survivor remains SURVIVED; its original different-
AppContainer profile still has no higher-effective-level negative witness.

Run `python -B tools/v04_mutations.py --out build/v04-mutations` after
`python -B tools/prepare.py`; output must be new. Mode/checkouts are recorded in the
replay report, not inferred from this initial result.

## Exact-SHA cold reproduction

At clean `6c015ce4d738890c0f64932e1bdfd9b845f61969`, the full validator
completed the five new mutations in normal, repeat and -O. Each mode reports
5 KILLED,0 SURVIVED,0 CRASHED,0 NOT_APPLIED,0 CONTROL_BROKEN.
All original/restored positive controls and byte-exact source restoration pass.
Historical15/11/3+1 populations reproduce separately in the same three modes.
Repeated executions do not multiply the number of unique mutants.
