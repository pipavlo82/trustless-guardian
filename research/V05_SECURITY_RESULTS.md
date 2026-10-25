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
