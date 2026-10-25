# Trustless Guardian

An experimental enforcement layer for AI-agent actions, with a reproducible
Windows filesystem pilot.

**Verification != Authorization != Enforcement != Evidence of Execution**

A policy refusal is useful only if the confined agent also cannot write around
the broker. This pilot runs a separate, non-elevated AppContainer process against
a disposable NTFS resource and checks the actual bytes from the trusted host.

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
| Dedicated least-privilege broker account, production service, crash recovery | PLANNED |
| Administrator/kernel resistance, universal agent containment | UNSUPPORTED |

Local results: 14 unit tests; 17 policy/resource scenarios; 9 direct OS-denial
operations with a writable-scratch positive control; unavailable-gateway/broker
controls; evidence-tampering rejection. The executed physical mutation campaign
contains **15 KILLED / 0 SURVIVED / 0 CRASHED / 0 NOT_APPLIED / 0 CONTROL_BROKEN**.
Normal, repeat and optimized semantic outputs match. See the
[measured results](research/CONFORMANCE_RESULTS.md) and
[mutation boundaries](research/MUTATION_REPORT.md), including untested boundaries.

## Reproduce

Use 64-bit Windows on NTFS and Python 3.12+ from a normal non-elevated terminal.
The agent runtime is pinned to CPython 3.12.10. No pip dependencies are needed.
Do not elevate to work around a failed isolation setup: report it as NOT_COVERED.

```powershell
git clone https://github.com/pipavlo82/trustless-guardian.git
cd trustless-guardian
git switch research/guardian-enforcement-v0
python -B tools/integrity.py
python -B tools/validate.py --out build/replay-1
```

For a published result, detach at its full commit before running. `validate.py`
runs normal/repeat/`-O` unit and OS tests, physical mutations, semantic comparison,
and inventory verification. Use a new output directory for every invocation.

```powershell
python -B tools/prepare.py
python -B tools/lab.py --out build/individual-lab
python -B tools/mutations.py --out build/individual-mutations
python -B -O tools/mutations.py --out build/optimized-mutations
python -B tools/validate.py --portable --out build/portable
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
- [Limitations](research/LIMITATIONS.md) and [independent review checklist](docs/REVIEW_CHECKLIST.md)

`main` contains the foundation. Experimental implementation stays on
`research/guardian-enforcement-v0` pending independent review. Original code is
[Apache-2.0](LICENSE); [third-party notices](THIRD_PARTY_NOTICES.md) preserve
separate licensing. No upstream source code is vendored.
