# v0.4 gap audit

Starting production revision: d64bef31fb35800be8af60e6d5a63d80a6afd020.
This is a same-engineer audit with a separate-process, implementation-independent
oracle. It is not an independent organization or second-machine certification.

Two defects were reproduced against exact original production bytes with the new
harness before accepting repairs:

| Finding | Actual witness | Repair |
| --- | --- | --- |
| G04-01 unexpected exception after write | Real permitted bytes are written; injected RuntimeError at WRITTEN escapes the selective broker exception tuple. Legacy server returns REFUTED / NOT_EXECUTED. Host reads changed bytes | Catch ordinary Exception at the broker stage boundary. New `guardian.dispatch.dispatch` also preserves uncertainty if a backend unexpectedly raises after returning from real execution |
| G04-02 ambiguous restart response | Abrupt process exit after real WRITTEN; restart recovers RECOVERY_REQUIRED but returns execution=NOT_EXECUTED for the same nonce | Recovery gate returns UNVERIFIABLE / RECOVERY_REQUIRED / retry_permitted=false |

Neither witness demonstrates an unauthorized write: the initial action was
permitted. They demonstrate false execution assertions. A DENY response after
execution may have started is not evidence that the action was prevented.

The new dispatcher preserves normal native broker results; it neither validates
receipts nor grants authority. Caller OS authentication precedes it. BaseException
termination is not converted to a fabricated response. Authentication, policy,
execution and evidence remain separate.

Historical v0/v02/v03 code populations and all old evidence remain attributable to
their original revisions. See the execution-outcome, impersonation and mutation
reports for precise domain restrictions. Native evidence-to-action integration
remains DESIGN ONLY / NOT_COVERED; see docs/EVIDENCE_TO_ACTION_CONTRACT.md.

## Evidence-to-action review

Read-only fetches again found clean checkouts with HEAD equal to origin/main:
ReceiptOS f39ac3b289be6baef1140c53976d525d8eb45c8c,
VECA e2aca1a029203f1d5c73db2f8872b4240e793bfb, and
recompute-kit b4537d73bda4e4df73c4b105ee516a43c351ba02.
Exact interface/license file hashes are in the v04 originals archive's
preflight/native-source-audit.json. These are source inspections, not new native
verification runs. No native adapter or upstream change is included: execution
outcomes and deployment-specific identity boundaries still need independent
review before any external evidence can participate in an action profile.

## Final research verdict

**HOLD for security release/merge; local gap repairs completed.** G04-01 and
G04-02 have real original/fixed/restored behavioral witnesses. The new controlled
impersonation-level witness closes a function-test gap, not a demonstrated
production bypass. Full-profile level>1 reachability remains NOT_COVERED and the
historical v03 survivor remains SURVIVED. Hosted reduced-token creation now works,
but child startup blocks before the enforcement suite. Cross-Windows enforcement
and independent human review remain NOT_COVERED.

No file/SQLite atomicity, exactly-once execution, power-loss safety, compromised
broker/host containment or arbitrary agent-action authorization is established.
The trusted host, provisioner, runtime/configuration, time source and recorded
observations remain assumptions. The two AppContainers share a base user and do
not prove different real-world controllers. Native ReceiptOS/VECA admission stays
DESIGN ONLY. No main/upstream change, merge, release or deployment is included.

See [machine-readable summary](V04_SUMMARY.json), [results](V04_CONFORMANCE_RESULTS.md),
[CI diagnosis](V04_WINDOWS_CI_DIAGNOSIS.md) and [evidence inventory](../evidence/README.md).
