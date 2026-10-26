# v0.4 execution-outcome invariant

Once a resource may have changed, lack of a completed response is not evidence of
non-execution. Catch ordinary backend exceptions conservatively; process crashes
and missing output remain unavailable outcomes, never successful enforcement.

| Boundary | Injection / actual operation | Expected observation |
| --- | --- | --- |
| PREPARING | Real SQLite query_only causes prepare write failure | UNVERIFIABLE/RECOVERY_REQUIRED response; no negative durable intent, unchanged bytes |
| Prepare return | Real durable INSERT followed by RuntimeError | Ambiguous response; unchanged observed state permits historical ABORTED tombstone on restart, not proof of no I/O |
| Resource write | Close the held handle before replace | Real invalid-handle failure; unchanged bytes; ambiguity retained |
| Partial write | Real shortened write/flush then OSError | Partial protected bytes; RECOVERY_REQUIRED on restart |
| Flush | Real write/truncate; call FlushFileBuffers on a deliberately invalid handle | Actual WinError6; changed bytes; not a spontaneous disk-failure claim |
| Readback | Close resource handle after real write | Actual invalid-handle error; changed bytes remain ambiguous |
| Readback mismatch | Trusted hook writes different actual bytes after replace | Actual readback mismatch refuses commit; physical removal demonstrates guard necessity |
| SQLite commit | Real second-connection BEGIN IMMEDIATE after write | SQLITE busy/locked; PREPARED intent and changed bytes; recovery refuses |
| Ordinary exception | RuntimeError after WRITTEN or COMMITTED, or after journal close | No definitive NOT_EXECUTED; exact durable state retained |
| Dispatcher return | Real broker finishes, wrapper raises before response | Independent dispatch boundary returns uncertainty; restart rejects consumed nonce |
| Crash/same bytes | Actual process exit73 at WRITTEN, including identical intended bytes | No invented response; restart reports RECOVERY_REQUIRED, including same-bytes ambiguity |
| Response loss/concurrency | Unchanged v03 lost-response and two-broker controls | Durable commit and replay refusal; no distributed exactly-once claim |

Fault configuration is trusted test infrastructure, inaccessible through the
action envelope. It is not evidence that storage spontaneously failed. Expected
bytes/states are declared in tools/v04_campaign.py before observations. A separate
oracle reads actual files and process tokens with standard library/Win32 calls;
it does not calculate expectations by calling Guardian's implementation.

The file/SQLite intervals remain non-atomic. PREPARED may persist before a response,
partial or same-byte writes can occur, and COMMITTED may precede response delivery.
No automatic retry, rollback, power-loss guarantee or universal exactly-once claim.

The ordinary REPLAY refusal describes the current attempted invocation. It is
not a historical status query for the original nonce: a prior COMMITTED write
can coexist with a refused retry. Likewise an ABORTED tombstone records a bounded
state-recovery decision, not proof that no physical I/O ever occurred. The API
still lacks a reviewed operation-status/reconciliation protocol; downstream
consumers must not infer historical non-execution from a retry refusal. This
limitation is not retroactively assigned as a guarantee to old evidence.
