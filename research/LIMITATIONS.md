# v02 limitations (current experiment)

- Distinct AppContainer principals share a base TokenUser. Separate Windows-account
  separation and a deployed least-privilege service are NOT_COVERED.
- OS witnesses cover one Windows/NTFS setup, selected APIs, one file and a trusted
  provisioner. No universal confinement, administrative resistance or hostile-host
  evidence authenticity is claimed.
- Authenticated local IPC uses a measured cross-AppContainer namespace path.
  Cross-build compatibility, flooding resistance and production configuration
  distribution remain open. Identification is not policy authorization.
- Partial writes remain possible. Recovery preserves ambiguity and refuses new
  actions; it does not supply atomic rollback or an automatic repair endpoint.
- Process termination hooks are real, but hardware power loss and arbitrary storage
  failure are not reproduced. Concurrency covers two clients and one server loop,
  not a distributed or multi-broker stress test.
- The worker uses a host-provisioned fixed laboratory clock for deterministic
  expiry witnesses. The request cannot select that clock. Production wall-clock
  sourcing, clock rollback resistance and a long-running expiry service are
  NOT_COVERED; the tests establish policy comparisons at the recorded time only.
- The independent oracle and fresh replay are author-operated on the same host.
  Independent third-party review remains NOT_COVERED.
- Native ReceiptOS/VECA/recompute-kit evidence-to-action bindings remain NOT_COVERED.
  A positive cryptographic or conformance result never grants filesystem authority.
- Hosted CI must be judged from exact-head run artifacts. Missing suitable Windows
  identity remains a failing enforcement gate, not a skip or simulated PASS.

The remaining text preserves v0 limitations and historical result scope.

# Remaining limitations and unsupported guarantees

1. **Finite Windows laboratory scope.** One file profile, one Windows host and
   selected access APIs do not establish universal AI-agent containment. No Linux,
   macOS, public deployment, real account takeover or third-party AI control was tested.
2. **Broker privileges.** The trusted broker API targets one file, but its normal
   user token has wider rights. A dedicated narrowly privileged service account
   or token and authenticated IPC remain unimplemented. Other unconfined same-user
   processes are trusted. A compromised broker can invalidate the guarantee.
3. **Actor meaning.** A distinct AppContainer SID is an OS restriction, not a
   separate Windows account or proof of distinct human control. Host identity
   and controlled test time must never be supplied by an untrusted remote caller.
4. **Crash/atomicity.** Nonce consumption, file write and evidence persistence are
   not one atomic transaction. A crash can consume a nonce without an action or
   leave a partial write/unrecorded action. Recovery, exactly-once execution and
   availability are not established. Only serial laboratory use is validated.
5. **TOCTOU and paths.** Exclusive handles, file identity and reparse checks narrow
   races but do not prove all Windows namespace, hard-link, device or concurrent
   administrative behavior safe. Hard-link write was unreachable in the OS witness.
6. **Evidence trust.** Hashes and an independently recomputed record do not attest
   an honest host. The record head and policy hash require an independent trusted
   selection. There is no signed durable log, hardware attestation or external
   timestamp authority. Whole-log rewrite by the trusted host remains possible.
7. **Policy adequacy.** `approved:` prefix and prior-file digest are intentionally
   narrow laboratory requirements. They do not determine whether a real AI action
   is socially, legally or operationally appropriate. Unsupported/malformed
   trusted configuration or OS errors can abort without a complete record; this
   is fail-closed absence of execution, not a successful conformance result.
8. **Integrations.** Native result envelopes preserve bytes but do not execute
   ReceiptOS/VECA verification or grant authority. No zkIE/WYRIWE/external receipt
   chain is demonstrated. ERC-8404 Core and native canonicalization stay unchanged.
9. **Testing independence.** Separate-process oracle and fresh checkout share an
   author, host and Python implementation. No independent external reviewer has
   validated this branch. Kernel bugs, network escapes and arbitrary AI frameworks
   are not covered. The job intentionally allows only one child process.
10. **Artifacts and installation.** CPython is integrity-pinned, not reproducibly
    built here. Disposable files are retained under ignored build storage; profile
    teardown runs on the normal harness path, but a killed harness may leave a
    profile requiring explicit cleanup. No production installation is provided.

These are remaining engineering obligations, not demonstrated vulnerabilities
in any audited upstream project. Recommendation: **ITERATE** before deployment.
