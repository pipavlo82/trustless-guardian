# v02 boundaries

| Boundary | Implemented mechanism | Remaining assumption |
| --- | --- | --- |
| Agent to broker | Named-pipe DACL, OS identification token, exact package SID | Trusted host provisioning and Windows kernel |
| Broker to assets | Separate AppContainer, scoped ACLs, no capabilities | Finite tested resources; no complete escape audit |
| Authorization | Canonical policy pin, exact envelope and unchanged finite policy | Policy adequacy and trusted laboratory time |
| Namespace/TOCTOU | Pinned directory identities, no delete sharing, exclusive files | Higher namespace ancestors and supported NTFS behavior |
| Recovery | Durable intent/tombstones, conservative ambiguity gate | No atomic transaction across SQLite and resource |
| Receipt | Separate oracle plus host snapshots | Hash integrity does not prove honest observation |
| Native evidence | Read-only pinned probes; native verdict retained | Evidence-to-action admission NOT_COVERED |

Current results are linked in the v02 result report. The historical v0 boundaries
below are retained; its broad broker token and missing recovery/IPC are not the
current v02 implementation.

# Security boundaries

| Boundary | What was established | What was not established |
| --- | --- | --- |
| Request to policy | Exact finite local policy; caller flags do not authorize | Correctness of arbitrary natural-language intent |
| Policy to broker | Independent recomputation, policy pin, file identity, nonce | Production IPC authentication or distributed revocation |
| Agent to file | Real AppContainer denied tested NTFS operations | Universal escape resistance, all Windows APIs or kernel correctness |
| Broker to file | Host observed exact allowed bytes and unchanged denied bytes | Atomic recovery across crash, file mutation and evidence recording |
| Record to verifier | Independent consistency and scope recomputation | Truth of a malicious host's entire fabricated log |
| Upstream proof/receipt to action | No automatic authority; native bytes preserved | Complete ReceiptOS/VECA/RVR integration or external execution chain |

Only newly created disposable lab directories receive ACL changes. The DACL
grants the AppContainer read/execute on protected data and write on its scratch
inbox. SYSTEM and the trusted broker user retain control. The sample resource is
deliberately assigned low mandatory integrity so the write-denial witness depends
on the DACL: the ACL mutation demonstrably enables a write. This does not change
system security settings or an existing user file's label.

The process receives no inherited handles, no AppContainer capabilities and only
an allowlisted environment. Its job limits active processes to one and kills the
child on job closure. Network isolation and every environment/handle escape path
have not been independently penetration-tested. No production secrets are loaded.

The ALLOW witness, writable scratch witness, zero child exit, OS-inspected token
and host before/after digests prevent an unavailable Python runtime from counting
as successful confinement. Startup errors fail the run.

Source hashes and log hashes establish identity/integrity. They do not establish
host honesty. A signed log would not change that limitation. No claim of remote
control over third-party AI systems is made.
