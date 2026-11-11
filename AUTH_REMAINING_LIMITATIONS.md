# Remaining Limitations

Production status is `HOLD`.

1. The trust root and ownership registry are local fixtures. No production identity provider, registry consistency protocol, or operational key ceremony is implemented or tested.
2. Replay state is bounded and thread-safe in one process, but it is not a durable, replicated nonce service. Cross-process restart and partition behavior remain unproved.
3. MCP bearer issuance, secure storage, rotation, audit, and emergency revocation are fixtures rather than an operational service.
4. The local Docker daemon is rootful. WSL user namespaces work, but a rootless container daemon and its end-to-end worker path are `NOT_COVERED`.
5. The worker image is a cached local research image, not a Guardian-built image with an independently reviewed SBOM, signed provenance, and vulnerability policy.
6. The container has network disabled. A future narrowly allowed egress design would require destination enforcement outside the container, DNS/rebinding defenses, SSRF validation, and independent bypass tests.
7. Host-kernel, Docker Desktop, WSL2, and hypervisor compromise are outside this pilot's threat boundary.
8. Production logging, alerting, durable evidence storage, privacy retention, and incident recovery are not exercised.
9. Hosted Linux cannot claim the local image checks when the pinned image is absent; it correctly reports `NOT_COVERED`.
10. Independent human cryptographic and containment review is still required.

Necessary next review: threat-model review, dependency/license review, cryptographic implementation review, a rootless Linux host replay, durable nonce/trust-root design review, and a production-like but strictly synthetic end-to-end staging exercise.
