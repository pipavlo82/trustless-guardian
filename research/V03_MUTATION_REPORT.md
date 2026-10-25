# v0.3 physical mutation report

New population: **3 KILLED / 1 SURVIVED / 0 CRASHED / 0 NOT_APPLIED /
0 CONTROL_BROKEN** in the first executed campaign. Each copy runs original,
one changed source file, exact restoration and the restored witness in separate
actual AppContainer processes. SHA-256 before/changed/restored is recorded.

| Mutation | Isolated witness | Observed divergence | Classification |
| --- | --- | --- | --- |
| ambiguous_failure | Real SQLite writer lock after resource write | Mutant says NOT_EXECUTED despite host-observed changed resource; repair says RECOVERY_REQUIRED at COMMITTING | KILLED |
| same_bytes | Real broker termination after flushing an identical-byte write | Mutant changes PREPARED to ABORTED and returns REPLAY for the consumed nonce; repaired state remains RECOVERY_REQUIRED | KILLED |
| base_user | Exact intended AppContainer SID but independently provisioned expected base-user hash differs | Removing only base-user comparison causes a COMMITTED write; baseline and restored refuse with unchanged bytes | KILLED |
| impersonation_level | Client requests SQOS impersonation; actual token is identification | Removing explicit level comparison changes nothing because OS downgraded the token | SURVIVED; boundary not exercised |

G03-01 is a reporting/recovery guarantee, not a claim that the original request
was unauthorized. G03-02 concerns preserving ambiguity, not evidence of a second
payment or replay. Both require the actual host byte observation and durable
journal state; a thrown exception alone cannot kill them.

The impersonation-level survivor is explicitly retained. It is not proven
equivalent over other Windows versions or caller configurations. A real effective
level>1 negative token is NOT_COVERED. The test runner validates this declared finite
experimental result and sets `coverage_complete=false`; it does not claim all
guards are covered. Anonymous-token refusal does not substitute for that witness.

Historical populations remain separate: v0 **15**, v0.2 **11**, new v0.3 **4**.
Normal and optimized replays repeat these populations; they do not double them.
Prior hosted CONTROL_BROKEN and launch failures remain in their original archives.
Complete mode/checkouts results are in [conformance results](V03_CONFORMANCE_RESULTS.md)
and [independent replay](V03_INDEPENDENT_REPLAY.md).

Reproduce: `python -B tools/v03_mutations.py --out build/v03-mutations`.
Use a fresh output directory and run `python -B tools/prepare.py` first.
