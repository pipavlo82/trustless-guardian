# Replay and challenge remaining limitations v1

Production remains **HOLD**.

- SQLite provides atomic local cross-thread and cross-process replay state for one filesystem and scope. Durable distributed state, replication, failover, corruption recovery, backup/restore semantics, and multi-host races are not covered.
- `PREPARED` is intentionally not auto-recovered. An operator must independently establish that the prior attempt is stopped before marking `RECOVERY_REQUIRED`; power-loss and kernel-level exactly-once execution are not claimed.
- The disposable local trust registry, JWT keys, SIWE wallet, MCP bearer, grant key, and receipt key are synthetic. Production issuance, rotation, revocation, custody, audit, and compromise response are not covered.
- Receipt verification authenticates the supplied local artifacts and their bindings. It does not prove that stdout is truthful, that a worker implementation is benign, or that a signed image was independently reviewed.
- The active WSL daemon lacked the exact pinned worker image. No pull was authorized or performed, so the v3 real-container replay is `NOT_COVERED` there. Rootless Docker daemon execution is also not covered.
- The local Windows caller was not elevated enough to start the inherited restricted native assessment. That result is `CONTROL_BROKEN`, not a Windows enforcement pass for this branch.
- The workflow file is bootstrap trust for the external integrity-policy pin and is not self-authenticating. Git commit identity and hosted CI readback remain necessary.
- No Vértice infrastructure, production service, production secret, client/NDA data, or third-party target was accessed.
- No merge, deployment, release, or production-readiness claim is authorized.
