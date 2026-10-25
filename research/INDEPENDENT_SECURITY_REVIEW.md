# v02 adversarial and independent-oracle review

This is an author-executed review using separate processes and a distinct oracle
implementation. Independent organizational/human review is **NOT_COVERED**.
The machine report and immutable evidence archive identify the executed revisions.

## Findings addressed

1. v0 broker had broad host-user access. v02 uses a different zero-capability
   AppContainer SID with narrowly provisioned resource/journal rights. Direct
   broker probes test outside-scope read/write, policy write, resource deletion
   and DACL changes. Host compromise and malicious privileged provisioning remain
   outside the boundary; no separate Windows-account claim is made.
2. v0 mailbox supplied actor context through the trusted harness. v02 identifies
   a live pipe client's OS token, then separately evaluates the request. A second
   principal is tested both against the pipe DACL and an intentionally permissive
   **test-only** DACL to isolate the token check. For the latter, the research
   policy permits both keys while the channel permits one; disabling only the
   channel check must cause an observable unauthorized write.
3. v0 nonce-before-write could leave an unexplained consumed nonce. v02 records
   intent and explicit recovery states. Physical partial/complete writes without
   COMMITTED are retained as ambiguity and block new actions. This does not remove
   the filesystem/database atomicity gap.
4. Parent directory identity and deletion sharing are now part of admission.
   A replacement parent containing the original child inodes is an isolated
   witness; ordinary file identity checks alone would not catch that substitution.

## Oracle and mutation discipline

The host supplies predeclared outcomes, executes real confined processes, checks
actual bytes after each direct operation, and retains raw child observations.
`guardian/verify_v02.py` imports neither broker, policy, IPC nor recovery code. It
recomputes the recorded positive authorization and exact scope from external pins.
It cannot prove an honest host or real OS behavior from a forged complete record.

Each new selected mutation is a physical edit in a disposable checkout with an
original ALLOW control, an isolated negative, a restored run and byte-exact source
restoration. KILLED requires actual unauthorized resource change, not an exception
or a changed Boolean. Historical v0 controls remain a separate population.
Coverage of kernel internals, every guard, every possible concurrency schedule,
or every broker-compromise path is not claimed.

## Remaining review priorities

- Independently reproduce the cross-AppContainer named pipe on another Windows
  build and assess its explicit namespace spelling.
- Review PID/OS-token authentication, identification-level reversion, pipe DACL,
  cancellation lifetime and trusted configuration distribution.
- Review recovery under storage faults, same-bytes writes and concurrent brokers.
- Review broker least privilege beyond the finite canaries, including implicit
  AppContainer storage, runtime loading, handles and network behavior.
- Review the hosted ephemeral-token reduction, if it executes, separately from
  the already witnessed local non-elevated path.
- Define an independently adequate evidence-to-action contract before consuming
  native ReceiptOS/VECA outputs as policy inputs. No automatic execution lift.
