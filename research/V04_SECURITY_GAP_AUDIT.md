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
