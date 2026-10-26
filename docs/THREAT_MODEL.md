# v02 threat-model extension

The protected asset remains one disposable NTFS file, its policy, pinned identities
and durable operation journal. The trusted host/operator provisions them. An
attacker controls the confined agent process and its requests, including bypass,
actor substitution and malformed IPC. The OS, runtime, launcher and authorized
broker implementation remain trusted.

v02 moves the broker into a different zero-capability AppContainer SID. It shares
the base Windows user with the agent and trusted provisioner; it is not a new
Windows account or a defense against malicious unconfined processes under that
user. The broker has scoped resource/journal grants and read-only policy/runtime.
Its implicit AppContainer facilities are not a proven total capability inventory.
The broker cannot elevate an identification-only client token into authority.

Non-elevation, low integrity, exact package SID, zero capabilities and non-inherited
handles are checked for launched confined processes. The profile uses a controlled
laboratory clock, not a production distributed freshness service. A compromised
broker could still abuse its declared resource and journal rights; the tested
outside-scope canaries demonstrate only bounded damage containment.

No persistent account, privileged service, UAC change, privilege enabling, runner
registration or machine-wide policy change is part of v02. Read
[IPC_SECURITY](IPC_SECURITY.md) and [CRASH_RECOVERY](CRASH_RECOVERY.md).
The following v0 section is historical and remains applicable where not superseded.

# Threat model v0

## Assets and authorities

The protected asset is the exact bytes of one disposable NTFS file. Policy bytes,
the policy digest, file identity and nonce ledger are also protected from the
confined agent. The trusted operator selects the policy and actor principal.
The actor is a per-run AppContainer SID, not a human identity or proof of separate
real-world control. The broker is the trusted host user process.

The attacker controls agent instructions, structured request contents and the
agent process's actions inside its restricted Windows token. It may ignore the
gateway and attempt direct filesystem access. Prompt instructions do not create
the boundary; the OS token and resource ACL do.

## Assumptions

- Windows, NTFS, Python runtime and the trusted host/harness are not compromised.
- The broker, trusted policy authority and policy-distribution context are honest.
- The launcher supplies genuine OS identity and a trustworthy time value. Tests
  use a fixed controlled clock; a production time service is absent.
- Protected directories are created by the trusted host and no unconfined
  malicious process shares that host user's privileges.
- The official embedded runtime matches its recorded SHA-256. This pin is an
  integrity check against the audited download, not reproducible compilation.

## Threats and controls

| Threat | Current control and residual risk |
| --- | --- |
| Forged caller ALLOW | Broker ignores it and recomputes; malformed extra fields refused |
| Actor/resource/scope substitution | Exact equality against trusted policy and OS principal; fixed broker path |
| Policy tampering | Agent cannot write policy; broker rereads exact pinned canonical bytes |
| Expiry/replay | Trusted-time bounds; protected SQLite nonce consumption; no distributed replay store |
| TOCTOU | Exclusive handles, fresh prior-byte digest, policy pin and file identity; no proof against all namespace races |
| Alternate path | Direct, extended-path and junction attempts exercised; reparse/multiple-link broker guard |
| Credential leakage | No credentials used or passed; minimal environment; general secret isolation is not demonstrated |
| Gateway/broker unavailable | No dispatch; confined agent's direct attempts still denied; availability is not guaranteed |
| Broker compromise | Out of scope; broker token has wider user privileges than its narrow API |
| Evidence forgery | Hash/decision/scope recomputation relative to trusted pins; complete hostile-host rewrite remains possible |

Direct deletion, rename, parent-directory rename, hard-link creation, native
CreateFile write access and policy-file writes are tested. Hard-link **write** was
not reached because link creation was refused. Arbitrary symlink varieties,
devices, named pipes, memory attacks and every Windows access method are not covered.

Administrator, SYSTEM, kernel compromise, hostile hypervisor, physical access and
arbitrary remote systems are out of scope. No elevation is needed for the observed
per-user AppContainer experiment. If local policy blocks it, stop the OS test and
report NOT_COVERED; do not weaken Windows settings.
