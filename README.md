> **v0.6 — real Hermes laboratory integration:** [demo and commands](demo/real-agent/README.md), [results](research/V06_REAL_AGENT_RESULTS.md), [machine summary](research/V06_SUMMARY.json), [mutation report](research/V06_MUTATION_REPORT.md), [tool protocol](docs/REAL_AGENT_TOOL_PROTOCOL.md), [security report](research/V06_SECURITY_REPORT.md), [limitations](research/V06_LIMITATIONS.md).
>
> A genuine model selects a tool; the native Hermes agent loop executes it inside a measured AppContainer. Guardian independently authorizes the request, and a separate observer checks real resource bytes. This is a narrow local experiment through an explicit Codex CLI inference relay. It is not native Nous authentication, arbitrary agent containment or production authorization. Hosted Windows enforcement remains CI_BLOCKED; the full report preserves historical and development failures.

> **Historical v0.5 — HOLD:** [demo and commands](demo/README.md), [executed results](research/V05_SECURITY_RESULTS.md), [machine summary](research/V05_SUMMARY.json), [limitations](research/V05_LIMITATIONS.md).
>
> The genuine Codex CLI starts inside a measured AppContainer. No model-backed task or native agent tool action ran: real-agent integration is **NOT_COVERED**. The separate scripted Windows demo passed five scenario groups, six native access denials and four physical mutations in normal/repeat/optimized cold replay. Hosted enforcement remains CI_BLOCKED. Historical repeated mutation controls also retain failures; the report preserves them rather than treating all checks as green. Reports below describe their own historical runs.

# v0.4 audit update

Experimental execution-outcome repairs and a controlled real Windows
impersonation witness are on the research branch. Start with the
[gap audit](research/V04_SECURITY_GAP_AUDIT.md),
[results](research/V04_CONFORMANCE_RESULTS.md),
[mutations](research/V04_MUTATION_REPORT.md),
[exact replay instructions](research/V04_INDEPENDENT_REPLAY.md), and
[independent Windows protocol](docs/WINDOWS_REPLAY_PROTOCOL.md).
Hosted enforcement remains CI_BLOCKED until actual execution is established.
The completed cold replay has25 unit tests and17/41/21/15 versioned scenarios in
normal/repeat/-O. New mutations:5 KILLED/0 SURVIVED; historical v03 remains3/1.
The hosted token-handle defect is isolated and repaired, but child startup still
blocks before enforcement. Release/merge recommendation: **HOLD**.
[Machine-readable v04 summary](research/V04_SUMMARY.json).
No production or universal containment claim. Prior reports below remain historical.

# Trustless Guardian

An experimental enforcement layer for AI-agent actions, with a reproducible
Windows filesystem pilot.

The implementation is on [the research branch](https://github.com/pipavlo82/trustless-guardian/tree/research/guardian-enforcement-v0),
with [Draft PR #1](https://github.com/pipavlo82/trustless-guardian/pull/1). `main` remains the foundation.

**Verification != Authorization != Enforcement != Evidence of Execution**

**v0.3:** [security audit](research/V03_SECURITY_AUDIT.md),
[executed results](research/V03_CONFORMANCE_RESULTS.md),
[mutation report](research/V03_MUTATION_REPORT.md),
[clean replay](research/V03_INDEPENDENT_REPLAY.md), and
[hosted CI blocker](research/V03_CI_ROOT_CAUSE.md).
The repair preserves uncertain post-write outcomes instead of claiming
NOT_EXECUTED. Hosted Windows enforcement remains **CI_BLOCKED**; the new
impersonation-level mutation **SURVIVES** because its adverse token level was
not reached. This remains a bounded laboratory prototype, not production security.

Full v0/v02/v03 replay from a non-elevated Windows Python 3.12+ process:
`python -B tools/validate_v03.py --out build/v03-replay`.
Use a new output directory. Portable checks:
`python -B tools/validate_v03.py --portable --out build/v03-portable`.
Portable success cannot certify OS enforcement.

A policy refusal is useful only if the confined agent also cannot write around
the broker. This pilot runs a separate, non-elevated AppContainer process against
a disposable NTFS resource and checks the actual bytes from the trusted host.
The v02 path also confines the broker under a different AppContainer principal,
authenticates named-pipe callers, and preserves explicit crash-recovery states.

## Current claim

**LABORATORY_VERIFIED:** the tested AppContainer principal cannot modify the
protected sample file through the exercised direct access paths. An allowed
request causes the broker to write exactly the approved bytes. Weakening the ACL
causes a real unauthorized write, which the mutation control detects.

This is a finite local experiment. It does not establish production readiness,
arbitrary execution authorization, resistance to a compromised broker, a complete
external evidence chain, or control over arbitrary remote AI systems.

| Component | Status |
| --- | --- |
| Gateway, versioned policy, fixed-resource broker, evidence recorder | IMPLEMENTED for the local file profile |
| AppContainer + NTFS denial and broker ALLOW | EXPERIMENTALLY VERIFIED on the recorded Windows host |
| Independent record recomputation and host byte observation | IMPLEMENTED; relies on trusted observation context |
| ReceiptOS / VECA native-result envelopes | Research interfaces only; native integration NOT IMPLEMENTED |
| Separate AppContainer broker, authenticated IPC, bounded recovery | IMPLEMENTED in v02; see measured scope |
| Dedicated Windows account and production service | NOT_COVERED |
| Administrator/kernel resistance, universal agent containment | UNSUPPORTED |

Historical v0 results: 14 unit tests; 17 policy/resource scenarios; 9 direct OS-denial
operations with a writable-scratch positive control; unavailable-gateway/broker
controls; evidence-tampering rejection. The executed physical mutation campaign
contains **15 KILLED / 0 SURVIVED / 0 CRASHED / 0 NOT_APPLIED / 0 CONTROL_BROKEN**.
Normal, repeat and optimized semantic outputs match. See the
[measured results](research/CONFORMANCE_RESULTS.md) and
[mutation boundaries](research/MUTATION_REPORT.md), including untested boundaries.

**v02 measured results:** 20 unit tests per mode; 41/41 adversarial cases in
normal/repeat/optimized runs; 11/11 new physical mutations killed, with no survivors
or crashes. This is separate from the historical 15-mutation population. See
[current measured results](research/CONFORMANCE_RESULTS.md),
[independent-oracle review](research/INDEPENDENT_SECURITY_REVIEW.md),
[IPC](docs/IPC_SECURITY.md) and [crash recovery](docs/CRASH_RECOVERY.md).

**CI_BLOCKED:** historical v0 Windows runs failed with WinError 1312. v02 creates
and verifies an ephemeral reduced token, but hosted process creation fails with
WinError 5 before OS tests. Portable CI passes. No accounts or token predicates
were changed to bypass the blocker. Consult [exact-run status](research/CI_PORTABILITY.md);
local success never substitutes for hosted execution.

## Reproduce

Use 64-bit Windows on NTFS and Python 3.12+ from a normal non-elevated terminal.
The agent runtime is pinned to CPython 3.12.10. No pip dependencies are needed.
Do not elevate to work around a failed isolation setup: report it as NOT_COVERED.

```powershell
git clone https://github.com/pipavlo82/trustless-guardian.git
cd trustless-guardian
git switch research/guardian-enforcement-v0
python -B tools/integrity.py
python -B tools/validate_v02.py --out build/replay-v02-1
```

For a published result, detach at its full commit before running. `validate_v02.py` retains the original regression suite and
runs normal/repeat/`-O` unit and OS tests, physical mutations, semantic comparison,
and inventory verification. Use a new output directory for every invocation.

```powershell
python -B tools/prepare.py
python -B tools/v02_campaign.py --out build/individual-v02-lab
python -B tools/v02_mutations.py --out build/individual-v02-mutations
python -B -O tools/v02_mutations.py --out build/optimized-v02-mutations
python -B tools/validate_v02.py --portable --out build/portable
```

The portable command tests policy and record logic only: OS enforcement is
NOT_COVERED. Windows commands create new per-user AppContainer profiles and
`build/guardian-lab-*` directories; ACL changes are confined to those disposable
directories. Profiles are removed on successful harness teardown. Lab files and
logs remain for inspection. Never point the broker at existing user resources.

## Review

- [Architecture and diagram](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md) and [security boundaries](docs/SECURITY_BOUNDARIES.md)
- [Source audit and exact pins](research/SOURCE_AUDIT.md)
- [Integration plan](docs/INTEGRATION_PLAN.md)
- [Evidence and replay](evidence/README.md)
- [Hosted CI portability and preserved failures](research/CI_PORTABILITY.md)
- [Limitations](research/LIMITATIONS.md) and [independent review checklist](docs/REVIEW_CHECKLIST.md)

`main` contains the foundation. Experimental implementation stays on
`research/guardian-enforcement-v0` pending independent review. Original code is
[Apache-2.0](LICENSE); [third-party notices](THIRD_PARTY_NOTICES.md) preserve
separate licensing. No upstream source code is vendored.
