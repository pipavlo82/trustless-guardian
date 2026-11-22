# Independent Authentication and Linux Isolation Defect Register

Scope: PR #5, based exactly on `e772eebd3ae3fee91237fa62b2caa3be0517684f`. Evidence is local and synthetic unless a hosted CI run is named. No Vértice system, credential, record, or endpoint is in scope.

## Priority register

| ID | Priority | Defect and reproduction | Disposition |
|---|---:|---|---|
| AUTH-001 | Critical | The PR #4 baseline has authorization replay research but no standard-library-backed gateway proving JWT, EIP-4361/EIP-191, registry ownership, MCP bearer scope, and request binding as one gate. A valid synthetic event could not establish cryptographic identity. | Fixed in `research/auth_gateway_v1`; disposable real signatures are required before authorization. |
| AUTH-002 | Critical | Signature validity alone did not prove role, wallet ownership, agent ownership, resource ownership, tool, destination, service, request ID, or canonical request-body identity. | Fixed with exact binding in three authenticators, an independent authorization policy, and a signed Ed25519 execution grant. |
| AUTH-003 | High | No atomic bounded replay state existed for JWT `jti`, SIWE nonce, and execution-grant ID. Concurrent reuse was therefore not independently disproved. | Fixed with a locked bounded nonce store; an eight-thread negative control admits exactly one request. |
| AUTH-004 | High | No independent verification path recomputed the JWT signature or recovered the SIWE EIP-191 address after the primary library accepted it. | Fixed with direct `cryptography` RSASSA-PKCS1-v1_5/SHA-256 verification and independent `eth-account` address recovery. |
| AUTH-005 | High | MCP authentication was not tied to subject, scopes, agent, resource, tool, destination, and service. | Fixed with a SHA-256-indexed opaque bearer registry and exact scope/request binding. Raw bearer values are never emitted as evidence. |
| AUTH-006 | High | An authorized request could be mutated before execution without a portable admission artifact that binds the body. | Fixed with a 60-second Ed25519 grant over canonical request binding. Mutated request and grant are refused before container start. |
| AUTH-007 | High | Trust-root availability, consistency, freshness, key rotation interval, key revocation, and wallet-registry expiry had no unified fail-closed gate. | Fixed for the local pilot. Production trust-root acquisition remains outside this branch. |
| DEP-001 | High | `siwe==4.4.0` requires `eth-account<0.14`; attempting `eth-account==0.14.0` produces an unsatisfiable dependency set. | Fixed by pinning `eth-account==0.13.7`. |
| DEP-002 | High | `siwe==4.4.0` permits `abnf<3`, but `abnf==2.9.1` fails while loading the RFC5234 grammar on import. | Fixed by pinning the working `abnf==2.4.0`; the complete transitive lock uses hashes. |
| DEP-003 | Medium | A lock compiled on Windows listed `pywin32` without a platform marker, so a Linux hash-locked install had no compatible distribution. | Fixed with an explicit `sys_platform == "win32"` marker and a successful WSL Linux `--require-hashes` install. |
| LINUX-001 | High | PR #4's Linux pilot did not cryptographically gate container admission. | Fixed locally: only a verified request-bound grant reaches `docker run`. Invalid grants and mutated requests start no container. |
| LINUX-002 | High | Local Docker Desktop is not a rootless daemon. Docker reports only built-in seccomp. | `NOT_COVERED`; user namespaces are independently available in WSL, but the tested container daemon remains rootful. |
| LINUX-003 | Medium | Hosted CI has no repository-pinned local worker image, and pulling an unpinned mutable image would weaken provenance. | `NOT_COVERED` in hosted CI by design. Local execution uses `--pull never` and records the cached image digest. |
| PROD-001 | Critical | Production trust roots, durable distributed nonce state, production MCP token issuance/revocation, and production worker admission are not connected or exercised. | Open. Production remains `HOLD`. |
| REVIEW-001 | High | Cryptographic code and isolation policy have not yet received an independent human security review. | Open. Required before any production claim. |

## Evidence discipline

- `FIXED` means reproduced against disposable local fixtures and covered by negative controls.
- `VERIFIED_LOCAL_PILOT` does not mean production verification.
- `NOT_COVERED` is retained when the host cannot demonstrate the property.
- No anomaly score is accepted by authentication, authorization, or execution admission.
