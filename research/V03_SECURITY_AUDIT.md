# Guardian v0.3 security audit

Scope: Windows local-file laboratory on the existing research branch. Starting
revision: `d4df3adf1a23ecd4158e97d97cef5e1a155097dd`. Protected main remains
`aaa941cf3566a6931cba539e4d8147d940459171`. First implementation revision:
`7e348a7d4de75f57bb3d0193b8870aeb646b0a20`.

This is a fresh source/executable review by the same engineering agent, with
separate host witnesses and clean checkouts. It is **not independent human
certification**. External reviewer and second Windows machine: NOT_COVERED.

## Confirmed findings and bounded repairs

| ID | Original observed behavior | Repair / evidence | Classification |
| --- | --- | --- | --- |
| G03-01 | Native SQLite lock acquired after real resource replacement causes commit failure; response says `DENY / UNVERIFIABLE / NOT_EXECUTED` while host observes changed bytes and PREPARED intent | Track PREPARING, PREPARED, WRITING, WRITTEN, COMMITTING, COMMITTED in memory. Any caught failure after prepare begins returns `execution=RECOVERY_REQUIRED`, exact failure_stage and retry_permitted=false. Restart refuses the ambiguous changed state. Physical guard removal reproduces the false NOT_EXECUTED result | Confirmed execution-reporting defect; repaired, laboratory witnessed |
| G03-02 | A same-byte write followed by process termination before COMMITTED is marked ABORTED on restart | If intended pre/post digests are equal, recovery now retains RECOVERY_REQUIRED. Physical removal restores ABORTED. Nonce remains consumed in either version | Conservative ambiguity hardening. Historical ABORTED meant observed unchanged state, not proof of no I/O; no unauthorized replay was demonstrated |
| G03-03 | Source did not explicitly query the pipe token's impersonation level | Query TokenImpersonationLevel, require identification, revert before authorization. A client requesting impersonation is actually downgraded to identification by the measured OS | Defense in depth. Removal SURVIVES; level>1 negative witness NOT_COVERED; no equivalent-mutant claim |
| G03-04 | Journal constructor could leave a connection open when schema inspection raised | Close the connection on all initialization failures; corrupted/missing/busy databases refuse before resource write | Resource cleanup repair; not a new authorization claim |

The original G03-01 request was policy-permitted. The defect was the false
execution assertion after an I/O failure, not an unauthorized agent write. DENY
after an operation starts is a refusal to certify/retry and must not be interpreted
as physical prevention. PREPARED and post-COMMITTED exception controls exercise
the same reporting boundary at different stages.

## Named-pipe audit

Reviewed `guardian/ipc.py`, `windows.py`, `protocol.py`, `broker.py`,
`hardened.py`, `gateway.py`, `recovery.py` and the executable harness.

| Boundary | Source contract and actual observation | Limit |
| --- | --- | --- |
| DACL | Actual GetSecurityInfo descriptor recorded. Host and broker full control; exact agent SID mask 0x12019b. Another AppContainer denied in v02; actual CreateNamedPipeW instance creation and WRITE_DAC client attempts denied with WinError 5 in v03 | Trusted host can change provisioning. Client CreateFile with the extra append bit can succeed; that is not a server-instance creation test |
| Caller | ImpersonateNamedPipeClient / OpenThreadToken; exact package SID, base-user SHA-256, low IL, non-elevation, zero capabilities. Isolated wrong-base-user expectation refuses; removing only this comparison permits a real write | Same base Windows user underneath both AppContainers; no proof of different controllers |
| Reversion | OpenThreadToken after authentication returns ERROR_NO_TOKEN (1008); resource access runs after RevertToSelf | Revert failure termination path reviewed, not forced in a real kernel failure |
| SQOS | Actual identification token recorded, including when client requests higher SQOS. Anonymous request refused | Higher effective level unavailable; explicit level guard is an uncovered survivor |
| Server identity | Trusted host inspects broker token and retains its process handle; client checks actual named-pipe server PID; v02 wrong-PID mutation is load-bearing | No PID-reuse stress proof; no production discovery service |
| Framing | Message pipe, one instance, first-instance flag, remote clients rejected. Malformed, duplicate, oversized, fragmented and concatenated documents refused | Finite payload tests; no denial-of-service resistance claim |
| Cancellation | Overlapped connect/read/write, bounded waits, CancelIoEx followed by completion drain; idle timeout and disconnect exercised | Completion draining depends on OS progress; no kernel-hang bound |
| Authorization | Authentication only supplies OS principal. Exact envelope/policy and action are independently evaluated with held resource handles | Adequate trusted policy and trustworthy clock are external assumptions |

Two early test expectations were wrong and are preserved: requesting SQOS=2 did
not yield an effective level-2 token; requesting client append access was not
equivalent to creating a pipe instance. The corrected tests measure the actual
token and invoke CreateNamedPipeW. They do not rewrite the first failed run.

## Recovery and concurrency

Two distinct live broker processes with the same resource, journal and nonce
were exercised. Broker A pauses at PREPARED while holding exclusive files;
broker B is refused with unchanged bytes. A commits exactly once; a new broker
refuses the consumed nonce. This is bounded local serialization, not distributed
exactly-once semantics. Lost response after COMMITTED preserves the receipt and
rejects replay. Missing, corrupted and exclusively locked SQLite files fail
closed before write. Crash and TOCTOU cases from v02 are rerun unchanged.

There remains a non-atomic interval between SQLite PREPARED and file writes, and
another between file flush/readback and SQLite COMMITTED. No rollback is inferred
from an exception. Same-byte writes cannot be distinguished by state digest alone.
See [recovery semantics](../docs/CRASH_RECOVERY.md).

## Remaining risks

Compromised host/kernel/administrator remains out of scope. Broker compromise is
bounded by the tested ACLs, not prevented. Trusted runtime/configuration and
higher directory ancestors remain assumed. Journal rollback/deletion by a trusted
host, arbitrary storage corruption, power loss, flooding, native verifier sandboxing,
clock rollback and all Windows escape routes are not established. Separate
Windows accounts and externally verified evidence-to-action integration remain
NOT_COVERED. No public deployment or production authority is created.

See [results](V03_CONFORMANCE_RESULTS.md), [mutations](V03_MUTATION_REPORT.md),
[CI diagnosis](V03_CI_ROOT_CAUSE.md), and [replay](V03_INDEPENDENT_REPLAY.md).
