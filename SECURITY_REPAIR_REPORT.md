# Guardian security repair report

## Verdict

**HOLD for production integration.** The repository repair gates and hosted Windows enforcement boundary are independently reproducible and `VERIFIED`. Production JWT/MCP/wallet provenance and a production rootless Linux host remain `NOT_COVERED`, so this branch is still research evidence rather than a production-ready Guardian.

## Scope and provenance

- Repository: `pipavlo82/trustless-guardian`
- Repair base: PR #3 HEAD `23bc33f81a7216b11efd7e614eb065275fd67a1e`
- Independently tested implementation commit: `93f0d2d68edf4cb31c3d477c766ddfd8e9f7b569`
- Green exact-SHA workflows: Security repair run `43050138530`; Guardian conformance run `43050138511`
- Historical PR #1 HEAD replayed unchanged: `03f6ffc6f4b983cfcc39f401f47165021e67e673`
- No merge, deployment, credential rotation, live-service access, Vértice access, or third-party target access was performed.

Evidence terms in this report are deliberate:

- **Independently verified** means executed in the repair worktree or an exact-SHA detached worktree.
- **Upstream reported** means read from an existing GitHub Actions artifact or check result and identified as such.
- **Inferred** means a bounded explanation, not a verified security property.

## Repaired boundaries

### Synthetic gateway replay

The v0 synthetic policy independently reproduced four false `ALLOW` results with no detector finding: admin subject confusion, owner/resource confusion, service subject confusion, and unsafe public-health shape. These are defects in the synthetic oracle; they are not evidence of a live production bypass.

The additive v1 oracle binds request subject, token subject, presented wallet, token wallet, role, resource owner, ownership proof, service, destination, and payload. Public health accepts one exact side-effect-free shape. Detection is a separate module and is never consulted to authorize an operation.

On the new separately constructed synthetic held-out corpus, v0 projection was `TP=4, FP=8, TN=80, FN=4`; v1 was `TP=8, FP=0, TN=88, FN=0`. These are deterministic fixture results only. Real-world generalization and statistical inference remain `NOT_COVERED`.

### Versioned integrity

The original 210-entry `artifacts.sha256.json` is byte-preserved with SHA-256 `7638540733f2654d4f95cd6e5294e7bdb4026c3e0a835a6a29092d41069303cb`. The 26 PR #2/#3 files are frozen in a separate pinned manifest. Repair additions are a third pinned layer. The current Guardian workflow is one explicit replacement that preserves the frozen prior digest and records the new digest; no historical digest is regenerated or reinterpreted.

The v1 verifier rejects missing, modified, unexpected, and unauthorized files; tampered control manifests; a tampered policy; missing bootstrap workflow; overlaps; unsafe paths; invalid types; and unpinned policy bytes. The policy hash must be supplied independently by the exact-SHA workflow or caller because a checkout cannot authenticate all of its own verifier bytes.

### Windows enforcement

The original local Windows 11 assessment executed 41 v0.2 cases and 15 v0.4 scenarios, but its non-elevated caller could not exercise hosted token reduction. Earlier hosted `CreateProcessWithTokenW` attempts reproduced a real `LpcReply` stall. `CreateProcessAsUserW` removed that stall but exposed `0xC0000142` for the direct LUA token. Positive controls proved the API and runner functional. A SAFER NormalUser/Medium stage started correctly; from that process, a direct LUA restriction of its own primary token started correctly without adding privileges.

The final launcher creates a disposable private window station/desktop with Low mandatory label and access for the same user and AppContainer packages. It never changes an existing ACL. Before resuming the final validator it independently observes the same user, Medium IL, administrators disabled, `elevated=false`, restrictions present, and only `SeChangeNotifyPrivilege`. The parent tokens are compared before/after and no manual privilege adjustment is performed.

On exact-SHA Windows Server 2022 run `43050138530`, the pinned runtime SHA-256 `4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3` was verified; v0.2 passed 41/41 cases; v0.4 passed 15/15 scenarios; and AppContainer identity, named-pipe authentication, broker permissions, nine file-access bypass attempts, execution/crash recovery, and restricted-token child startup all returned `VERIFIED`. Report SHA-256: `a0dc2fa3a4e8dea3689fe251703a260f3052120fbd2dda98e66a70f21420ef7c`. The separately updated Guardian conformance run `43050138511` also passed its portable frozen replay and current Windows gate.

### Linux isolated-worker pilot

The local Docker Desktop/WSL2 pilot used only an already-cached image pinned as `curlimages/curl@sha256:08e466006f0860e54fc299378de998935333e0e130a15f6f98482e9f8dab3058`. It independently observed non-root UID 65534, `NoNewPrivs=1`, zero effective capabilities, read-only rootfs, bounded tmpfs, `network=none`, TEST-NET denial, PID/memory/CPU/nofile limits, host-side synthetic bearer rejection, scoped request rejection, and clean recovery. Report SHA-256: `571f206d7fee0007ce51fb4f1ab6ffc66dd8d913db44bc1625d670987b273741`.

This is `VERIFIED_LOCAL_PILOT`, not production enforcement. The daemon was not rootless, and authenticated production invocation is `NOT_COVERED`.

## Independent test summary

- Unit suite: 177 tests, normal/repeat/Python `-O`, all passed locally.
- Gateway input/report mutants: 15 `KILLED`; zero `SURVIVED`, `NOT_APPLIED`, `CRASHED`, or `CONTROL_BROKEN`.
- Gateway physical source mutants: 16 `KILLED`; all had passing baselines and restored controls.
- Integrity physical mutants: 11 `KILLED`; all had passing baselines and restored controls.
- Historical PR #1 detached replay: portable chain and frozen integrity both exited 0; report SHA-256 `a7de0132bdba8397fee02e298cad70dd7cb4d160390df61b7a9fd3596cfadfd5`.
- Hosted Windows native assessment: `VERIFIED` on exact-SHA run `43050138530`, with 41/41 v0.2 cases and 15/15 v0.4 scenarios.

Exact commands and evidence boundaries are in `INDEPENDENT_REPLAY.md`; every non-final mutation run is preserved in `MUTATION_REPORT.md`.

## Gate decision

The repository and hosted Windows repair gates are closed. Production readiness is still refused because synthetic bearer/identity fields do not prove real JWT signature, issuer, audience, expiry, nonce, wallet control, registry state, MCP bearer validation, or authenticated event origin, and the Linux result is a local synthetic pilot rather than a production rootless host. Those integrations require their own design, deployment-specific evidence, and independent review. Until then: **HOLD**.
