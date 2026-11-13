# Resonance Guardian isolated core + IPC security report (research)

Base: exact Guardian Draft PR #6 head `457148f43d0cfb28b4c7c88bbf8a1d92963d77ab`. This branch is a new standalone research integration and does not alter Guardian Core or existing PR history.

## What local Windows experiments establish

1. Byte-identical original Resonance `agent.py`, three `State/decide` steps, bounded *synthetic* 7-channel telemetry inside a zero-capability low-integrity AppContainer; temporary Python runtime and AppContainer profile deleted.
2. `ImpersonateNamedPipeClient` / `OpenThreadToken` / `GetTokenInformation` authenticate the requesting AppContainer SID to a **separate** host broker; the named pipe uses an explicit SID-aware ACL.
3. Correct request/nonce receives `HOLD_GUARDIAN_GRANT_REQUIRED`, with **no** grant and **no** execution; mutated nonce and tool are denied, ordinary host client is denied, absent broker is denied.
4. Child client opening two specific Docker named pipes by `CreateFileW` receives Win32 `ERROR_ACCESS_DENIED=5`; host positive controls passed in earlier independent experiments.
5. Machine-evidence verifier with 16 in-memory mutations rejects every mutation in normal/repeat/optimized Python. Exact source SHA-256 checks and fail-closed error paths are pinned.

## What is NOT proven

- **Mutual authentication**: the client does not yet authenticate broker identity with independently anchored key material. The trusted host or malicious pipe server could impersonate the broker.
- **Guardian crypto grant**: broker deliberately does not issue JWT/SIWE/Ed25519 grants; this new IPC request is NOT connected to a scoped, durable PR #6 grant or to a real Docker worker. Older external lab experiments exercised those elements separately; they are NOT proof of this particular IPC composition.
- **No universal sandbox**: AppContainer isolation is bounded to the tested token, access masks, path/pipe handles, process and OS version. Not tested: all Docker pipes, TCP/WSL, arbitrary local sockets, privileged host compromise, all child processes or alternative tool paths.
- **Persistence**: synthetic observations are not host sensors; `measure()` is stubbed. This is not the full Resonance v5 loop with Codex, SQLite, forecasts or MiroFish.
- **Replay**: nonce is single-connection, not durable across broker restarts. No distributed replay-state or crash recovery.
- **CI**: a successful portable job does not certify native Windows enforcement. Hosted native job must explicitly report `VERIFIED_LOCAL_NATIVE_IPC` or `NOT_COVERED`.
- **Proof root**: local evidence can be recomputed but broker signer authority/OS attestation and independent second-host review remain NOT_ESTABLISHED.

## Required next gates

Establish independently pinned broker identity *to the AppContainer client*, durable session-bound challenge/grant authorization, native worker that independently checks signed grants, strict output/receipt recomputation and multi-machine negative controls. Do not use private keys inside the agent, widen user-installed Python ACLs, publish old local evidence or enable autonomous tools.

**Verdict: BOUNDED_WINDOWS_LOCAL_IPC_VERIFIED / BROKER_MUTUAL_AUTH_HOLD / EXECUTION_HOLD / PRODUCTION_HOLD.**
