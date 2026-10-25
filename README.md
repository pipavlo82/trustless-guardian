# Trustless Guardian

An experimental enforcement layer for AI-agent actions, with a reproducible
Windows filesystem pilot.

The implementation is on [the research branch](https://github.com/pipavlo82/trustless-guardian/tree/research/guardian-enforcement-v0),
with [Draft PR #1](https://github.com/pipavlo82/trustless-guardian/pull/1). `main` remains the foundation.

**Verification != Authorization != Enforcement != Evidence of Execution**

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
