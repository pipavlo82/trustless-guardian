# v0.5 security results

Scope: a local synthetic Windows laboratory, same base user and distinct agent /
broker AppContainer principals. **Real-agent task acceptance: NOT_COVERED.**

| Scripted OS control | Independently observed outcome |
|---|---|
| ALLOW | Native broker COMMITTED; exact bytes `approved:demo-source` |
| DENY protected configuration | REFUTED; all sampled files unchanged |
| BYPASS write/delete/rename/extended path | Native WinError 5; protected bytes unchanged |
| Protected-config write / synthetic-secret read | Native WinError 5 |
| POLICY CHANGE | Removed actor under freshly pinned canonical policy; REFUTED |
| Post-write ordinary exception | Actual `approved:ambiguous` bytes; UNVERIFIABLE / RECOVERY_REQUIRED, retry false |

There are five scenario groups and six native bypass attempts. Each direct
attempt has its own confined process and successful scratch-write positive.
Separate host snapshots inspect every attempt and recompute exact byte hashes
and native file identities. The record verifier also checks canonical policy,
request, receipt and observed IPC identity bindings. Host evidence is trusted
measurement, not remote attestation.

The demo's first construction attempt failed because a legacy helper retained
the old logical resource ID. The second run exposed an oracle precision issue:
Python's high-level file error omitted `winerror`, and a post-write exception
left durable PREPARED before reconciliation. The final demo uses native Win32
calls to preserve exact error 5 and declares that state precisely. Those failed
runs are preserved; neither was a demonstrated Guardian bypass.

The final machine-readable replay records exact source hashes, commands, exit
codes, normal/repeat/optimized results and semantic comparisons. A portable
captured vector tests the independent oracle only; it is not a Windows replay.

No Guardian implementation was changed in v0.5. Historic source/evidence,
mutation survivors and failure reports remain preserved. Hosted Windows still
cannot reach Python startup under its reduced token; see the historical
[v0.4 diagnosis](V04_WINDOWS_CI_DIAGNOSIS.md). CI remains blocked for enforcement.

## Final cold replay

Exact tested code: `f2a25fc8ed2d1de6cb84e661d77eeeb039d5c3ec`, detached clean
checkout; Windows 11 build 26200 x64, Python 3.12.10, non-elevated medium-integrity
host. All 62 delivered Python sources are compared byte-for-byte with that
commit. Subsequent publication changes are documentation and evidence only.

| Test population | Normal | Repeat | Python -O |
|---|---|---|---|
| Current unit tests | 33/33 | 33/33 | 33/33 |
| v0 policy scenarios | 17/17 | 17/17 | 17/17 |
| v0.2 scenarios | 41/41 | 41/41 | 41/41 |
| v0.3 scenarios | 21/21 | 21/21 | 21/21 |
| v0.4 scenarios | 15/15 | 15/15 | 15/15 |
| v0.5 scripted OS scenario groups | 5/5 | 5/5 | 5/5 |
| v0.5 direct native denials | 6/6 | 6/6 | 6/6 |
| v0.5 physical mutants | 4 KILLED | 4 KILLED | 4 KILLED |
| Genuine AI-agent task acceptance | NOT_COVERED | NOT_COVERED | NOT_COVERED |

The historical scenarios were replayed at exact starting commit
`36d9b28682ceee7c59e9860203342c56304ed6d8`. Their source remains unchanged.
Their 25-unit baseline passed; the current 33 includes eight added portable
oracle/adapter tests. These counts are not additive independent test populations.

The v0.5 semantic report is byte-identical in all three modes:
`25f1b0c280e079ab5774ca65b2564cec40b729cabaa13916460f15546b1e2c4e`.
This excludes dynamic PIDs, package SIDs, elapsed times and file IDs; raw runtime
outputs are not claimed to be identical across machines. The explicit real-agent
gate returned exit 3, despite passing laboratory controls.

## Historical replay qualifications

The concurrent aggregate historical replay **failed**, despite all scenario
matrices passing. Six repeated/optimized historical mutation campaigns had
CRASHED or CONTROL_BROKEN runs. All are retained. A separate serial replay then
produced the following; it also **failed** overall and is not labelled green:

| Historical mutation population | Serial repeat | Serial -O |
|---|---|---|
| v0.2 | 11 KILLED | 11 KILLED |
| v0.3 | 3 KILLED / 1 SURVIVED | 3 KILLED / 1 SURVIVED |
| v0.4 | 4 KILLED / 1 CONTROL_BROKEN | 3 KILLED / 2 CONTROL_BROKEN |

Normal v0/v0.2/v0.3/v0.4 mutation populations reproduced respectively
15 KILLED, 11 KILLED, 3 KILLED / 1 SURVIVED, and 5 KILLED. v0 repeat/-O each
reproduced 15 KILLED. The remaining old v0.4 control failures include a lost IPC
reply in an original positive control; they cannot certify mutation coverage.
Scheduling/IO pressure is an inference, not an established root cause. The
separate 8-second v0.5 demo timing profile passed its own cold controls, but does
not retrospectively repair or relabel these historical runs.

See [machine summary](V05_SUMMARY.json), [mutation details](V05_MUTATION_REPORT.md),
and [limitations](V05_LIMITATIONS.md). Overall acceptance remains **HOLD**.
