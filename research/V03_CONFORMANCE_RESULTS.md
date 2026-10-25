# v0.3 conformance results

Status: **LABORATORY_VERIFIED** for the finite exercised local Windows boundaries;
**HOLD** for production security, hosted enforcement CI and unrestricted native
evidence admission. External human review and second-machine enforcement are
NOT_COVERED. No security certification is claimed.

## Baseline

Fresh public clone pinned to `d4df3adf1a23ecd4158e97d97cef5e1a155097dd`:
normal/repeated/optimized unit tests 20 each, v0 17 scenarios each, v02 41 scenarios
each; semantic outputs identical within each suite. v0 15 KILLED and v02 11 KILLED,
zero other categories. All seven historical archive inventories verified and the
original 72-file inventory matched. Original v03 witnesses were then run against
unchanged d4 production modules; their failures are preserved separately.

## Current experiment

The complete local validator passed, with production/test source hashes matching
implementation revision `7e348a7d4de75f57bb3d0193b8870aeb646b0a20`. It started in
the working checkout before that commit; it is not described as a clean checkout.
The subsequent clean replay is recorded separately in V03_INDEPENDENT_REPLAY.

| Suite | Normal | Repeat | Python -O |
| --- | --- | --- | --- |
| Units | 22 passed | 22 passed | 22 passed |
| v0 scenarios | 17 expected | 17 expected | 17 expected |
| v02 scenarios | 41 expected | 41 expected | 41 expected |
| v03 scenarios | 21 expected | 21 expected | 21 expected |
| v03 physical mutations (same population) | 3 KILLED / 1 SURVIVED | Not separately run | 3 KILLED / 1 SURVIVED |

The v0 15 and v02 11 physical controls also passed, separately. The real
inheritable-handle control passed. All subprocesses exited 0. Each mode's v03
semantic.json SHA-256 is
`fae96bb69da6e96263dde67cf340d3dc35bc86d0987634d52cd54ba1ba6dc1db`.
All modes also matched within the v0 and v02 suites. These are semantic results;
timestamps, paths and Windows identities are not claimed byte-identical.

| New boundary | Actual witness |
| --- | --- |
| Post-write journal failure | SQLite BEGIN IMMEDIATE lock after real file replacement; explicit uncertain outcome, restart blocks |
| Exception after PREPARED | Unchanged bytes, uncertain reply, ABORTED tombstone after restart, nonce refused |
| Exception after COMMITTED | Changed bytes and durable receipt; uncertain response does not authorize a retry |
| Same-byte crash | Real process termination after write; RECOVERY_REQUIRED retained |
| Base-user mismatch | Correct package SID but wrong independently provisioned user hash; unchanged bytes |
| SQOS request | OS downgrades requested impersonation to identification; explicit guard coverage remains absent |
| Identification positive | Exact policy-permitted write through real authenticated pipe |
| RevertToSelf | OpenThreadToken afterward fails with ERROR_NO_TOKEN 1008 |
| Effective token | Exact expected AppContainer/base user, low IL, no elevation/capabilities |
| Anonymous client | Refused, no write |
| Server-instance attempt | Agent CreateNamedPipeW rejected with WinError 5 |
| Pipe WRITE_DAC attempt | Rejected with WinError 5 |
| Fragmented JSON | Separate pipe messages never combine into an authorized action |
| Two JSON objects in one frame | Refused by exact parser |
| Wrong base-user IPC context | Refused before action dispatch |
| Lost response after commit | Host sees expected bytes and stored receipt; restart replay denied |
| Direct bypass | Write/delete/rename/ACL attempts each OS-rejected; host snapshots unchanged |
| Missing journal | Dependency refusal; no silent reprovisioning or resource write |
| Corrupt journal | Native SQLite error; no resource write |
| Locked journal | Native SQLite contention before prepare; no resource write |
| Two broker processes | Same nonce/resource, exclusive file handles, one commit; loser and restart refuse |

The repeated base-user checks are one isolated mutation witness and one ordinary
transport case, not two distinct guarantees. 21 scenarios is a finite case count,
not a measure of universal coverage. Existing v02 controls additionally exercise
policy/resource/parent replacement, hardlinks, symbolic links, timeouts, nine
direct bypass paths, five broker-scope probes and four crash stages. The inheritable
parent-handle witness remains separate and is rerun.

## Preserved failures and limitations

The initial v03 campaign had two incorrect harness expectations (higher requested
SQOS and extra CreateFile append rights). Actual OS observations corrected the
oracle; no production predicate was weakened. Original raw outputs remain archived.
The new population has 3 KILLED and 1 SURVIVED; the survivor is explicitly uncovered.
Do not combine historical 15/11 and new 4 as a single historical experiment.

Same resource bytes cannot establish absence of past I/O. A crash hook is deliberate
process termination, not power-loss testing. Readback/flush is not a transaction with
SQLite. The laboratory clock is fixed by trusted configuration. The host, policy
authority, Windows kernel and pinned runtime remain trusted.
