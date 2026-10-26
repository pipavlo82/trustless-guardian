# v0.4 execution-outcome correction

The broker now catches every ordinary Exception after entering execution, not
only a selected exception tuple. Its stage guard preserves uncertainty. The
separate dispatch boundary also preserves uncertainty if a backend raises outside
that guard. Termination or missing output produces no fabricated successful
response. Unknown outcomes never authorize automatic retries.

A restart seeing PREPARED / RECOVERY_REQUIRED now returns execution=RECOVERY_REQUIRED,
status=UNVERIFIABLE, retry_permitted=false. The old recovery-gate response mixed an
ambiguous reason with NOT_EXECUTED, which could misstate a prior same-nonce write.
Historical ABORTED retains its limited observed-state meaning; file and SQLite
still are not atomic. [Exact fault boundaries](../research/V04_EXECUTION_OUTCOME_AUDIT.md).

# v0.3 recovery refinement

The four durable states remain PREPARED / COMMITTED / ABORTED / RECOVERY_REQUIRED.
There is still no atomic transaction joining SQLite and NTFS. New behavior:

- A caught failure from PREPARING onward returns UNVERIFIABLE, DENY,
  execution=RECOVERY_REQUIRED, failure_stage and retry_permitted=false. DENY here
  refuses certification/retry; it does **not** assert that bytes were untouched.
- In-memory stages are NOT_STARTED, PREPARING, PREPARED, WRITING, WRITTEN,
  COMMITTING and COMMITTED. They diagnose a response, not a new durable schema.
- A same-byte intended write with no COMMITTED record remains RECOVERY_REQUIRED.
  An unchanged digest cannot decide whether that write occurred. Other ABORTED
  tombstones retain the limited meaning documented below, with nonce consumed.
- Journal constructor failures release the connection; missing/corrupt/busy
  dependencies fail closed. No missing journal is silently recreated.

Native SQLite contention after a real file write reproduces the old false
NOT_EXECUTED response. New positive/negative/restored controls inspect the actual
resource and journal. Exceptions at PREPARED and COMMITTED, unexpected termination,
partial writes and lost responses are separately exercised.

Two simultaneous broker processes on the same pinned resource and journal were
tested. The first holds exclusive handles at PREPARED; the second refuses without
writing. The first commits once and restart rejects its nonce. This extends the
old single-broker/two-client control only for this local one-resource case. It does
not establish multi-resource transactions, distributed recovery or power-loss
durability. No ambiguous operation is automatically retried or rolled back.

Precise unresolved windows: a prepare transaction may finish before its caller
observes success; resource writes can be partial; flush/readback can finish before
journal commit; commit can finish before a response is delivered. The durable
record and state observation must be inspected before any operator recovery.
There is no production recovery/status-query API or log rollback protection.

See [v03 results](../research/V03_CONFORMANCE_RESULTS.md).

## Historical v0.2 behavior (preserved)

# Bounded v02 recovery

Resource bytes and SQLite are **not one atomic transaction**. The implementation
makes ambiguity explicit and stops further writes when it cannot establish a
safe state. It does not promise rollback, exactly-once external execution, power
loss durability across arbitrary storage hardware, or recovery of other resources.

| State | Meaning and permitted transition |
| --- | --- |
| PREPARED | Request/policy/pre/post digests and resource identity durably recorded before resource write; nonce reserved |
| COMMITTED | Exact write/readback and receipt recorded in one SQLite transaction; never replay this nonce |
| ABORTED | On restart the current bytes equal the preserved pre-state under the same resource/policy identity; keep nonce tombstone |
| RECOVERY_REQUIRED | Current bytes/identity cannot establish an unchanged pre-state; refuse all new writes |

Unknown journal states, missing database, incompatible schema, malformed data or
unavailable dependencies fail closed. The broker never silently recreates a
missing database. COMMITTED stores the complete receipt in the same database
transaction as that state, so response loss does not discard the durable receipt.

ABORTED does not prove that no CPU or file I/O occurred. A no-op write could have
left identical bytes. The meaning is only unchanged observed pre-state plus a
permanently consumed nonce. Exact intended post-bytes without COMMITTED still
produce RECOVERY_REQUIRED: matching bytes do not establish a completed protocol.

## Handle and namespace boundaries

The broker pins root/secure/journal directory identities from host provisioning,
holds directory handles without delete sharing for its lifetime, then opens the
policy and resource exclusively for each operation. Reparse files and files with
multiple hard links are rejected. Policy canonical bytes/hash and both file
identities are rechecked. Authorization is recomputed while those handles remain
held. The SQLite intent precedes the in-place write, flush and readback.

This fixes the tested parent substitution and concurrent namespace changes inside
the disposable root. Higher ancestors and host provisioning remain trusted.
There is no general proof about every Win32 namespace, filesystem, sharing mode,
storage device, backup restore, or an attacker with host-user privileges.

## Executed crash design

The test worker can abruptly terminate its own real broker process after PREPARED,
after a deliberately injected partial resource write, after complete write, or
after COMMITTED. These hooks are trusted laboratory configuration, inaccessible
through the action envelope. The partial-write control writes actual partial
bytes and exits; it is **not** a claim that Windows spontaneously produced a short
WriteFile result or that power was removed from hardware.

The independent host reads the bytes, restarts a new broker under the same scoped
principal and immutable configuration, inspects the journal and attempts replay.
Separate controls attempt policy/resource writes and directory renames while
PREPARED is paused with handles held. Two simultaneous clients exercise nonce
reuse through the serialized pipe loop. Multi-broker/distributed concurrency,
manual repair, rollback, journal retention/migration and throughput remain open.
