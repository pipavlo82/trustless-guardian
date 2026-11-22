# Replay and challenge security repair v1

Date: 2026-11-12 America/New_York

Base: exact Draft PR #5 head `5d98af242d4869d07bbfa6c5fb0028d7bb31d67d`.

This additive research branch closes a bounded replay gap without changing `main` or any earlier PR branch. It does not access Vértice, production credentials, client data, or third-party targets.

## Enforced boundary

- A SIWE request begins with a server-issued challenge stored in SQLite under a fixed admission scope.
- The challenge binds wallet, session, request ID, canonical request digest, domain, URI, chain, nonce, issued time, expiry, and exact resources.
- Challenge consumption is an atomic `ISSUED -> CONSUMED` update. Cross-session use, unsolicited challenges, expired challenges, concurrent reuse, and reuse after process restart are refused.
- A 60-second Ed25519 grant additionally binds the admission scope, worker SHA-256, exact image identity, trust version, grant key, principal, authorization result, and canonical request.
- Durable admission records transition from `PREPARED` to exactly one terminal state: `COMMITTED`, `ABORTED`, or `RECOVERY_REQUIRED`. Every recorded state blocks grant reuse after a restart. An incomplete `PREPARED` record requires an explicit recovery transition and is never retried automatically.
- Container execution requires a separately observed Docker container ID. A Docker CLI return without that witness is `RECOVERY_REQUIRED`, never `EXECUTED`.
- The signed execution receipt binds the request, grant bytes and signature, principal, worker, image, scope, trust version, lifecycle, observed output digests, and evidence digest. A separate read-only verifier recomputes the supplied artifacts and rejects signed type confusion and lifecycle contradictions.

## Independent local results

Windows and WSL Linux each passed:

- inherited Guardian regression: 177 PASS, 0 FAIL, 0 ERROR, 0 SKIP per normal, repeat, and Python optimized run;
- PR #5 authentication regression: 58 PASS, 0 FAIL, 0 ERROR, 0 SKIP per normal, repeat, and Python optimized run;
- replay/challenge/receipt assessment: 53 PASS, 0 FAIL, 0 ERROR, 0 SKIP per normal, repeat, and Python optimized run;
- replay/challenge/receipt physical mutations: 19 KILLED, with zero survivors, not-applied, crashes, or broken controls.

The pre-resume evidence is retained separately. It had 48 passing tests but only 15 KILLED / 1 SURVIVED in the first 16-mutation population. The survivor was not relabeled; an explicit pre-inspected concurrent-consume witness was added, after which that mutation was killed. Later container-start and receipt controls increased the final population to 19.

## Platform result

The available WSL Docker daemon was independently observed, and WSL user-namespace creation was verified. The exact previously pinned `curlimages/curl` digest was not present in that daemon. No image was pulled, so the real-container v3 replay is `NOT_COVERED` on this daemon. The daemon itself did not report rootless mode.

The local native Windows launcher correctly returned `CONTROL_BROKEN / ELEVATED_CALLER_REQUIRED` from the current non-elevated caller. It was not relabeled as a pass. Previously published PR #5 hosted Windows evidence remains historical evidence for PR #5, not a new PR #6 native result.

## Verdict

The bounded portable replay/challenge/receipt controls are ready for Draft review. Production remains **HOLD**. There is no exactly-once execution claim, no production trust-root or distributed replay-state claim, and no merge or deployment authorization.
