# Guardian security repair report

## Verdict

**HOLD.** The repair closes reproducible synthetic authorization/detection defects and restores additive inventory verification, but the required hosted Windows restricted-token child-startup property is still `NOT_COVERED`. This branch is research evidence, not a production-ready Guardian.

## Scope and provenance

- Repository: `pipavlo82/trustless-guardian`
- Repair base: PR #3 HEAD `23bc33f81a7216b11efd7e614eb065275fd67a1e`
- Independently tested implementation commit: `d0a7cbf593d4563ef0406b00b76331980934da59`
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

The original 210-entry `artifacts.sha256.json` is byte-preserved with SHA-256 `7638540733f2654d4f95cd6e5294e7bdb4026c3e0a835a6a29092d41069303cb`. The 26 PR #2/#3 files are frozen in a separate pinned manifest. Repair additions are a third pinned layer. No historical digest is regenerated or reinterpreted.

The v1 verifier rejects missing, modified, unexpected, and unauthorized files; tampered control manifests; a tampered policy; missing bootstrap workflow; overlaps; unsafe paths; invalid types; and unpinned policy bytes. The policy hash must be supplied independently by the exact-SHA workflow or caller because a checkout cannot authenticate all of its own verifier bytes.

### Windows enforcement

On local Windows 11, the independent assessment executed 41 v0.2 cases and 15 v0.4 scenarios. AppContainer identity/isolation, named-pipe authentication, broker permissions, nine file-access bypass operations, and execution/crash recovery were `VERIFIED` locally. A fresh clone initially returned `CONTROL_BROKEN` because the ignored embedded test runtime was absent; no security PASS was taken from that run. After fetching the source-pinned runtime and verifying SHA-256 `4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3`, the fresh-clone campaigns exited 0 and returned the same 41/15 coverage. The post-prepare fresh report SHA-256 is `6e81257a1ef7330267b0c129acc4e9d9d2b87a6b407eb2d11dfaad3e0eff0a7b`.

Restricted-token child startup was `NOT_COVERED` locally because the assessment caller was not elevated. In the existing Windows Server 2022 hosted artifact, five reduced-token attempts were created and resumed but remained `STILL_ACTIVE` with wait timeout and thread `WaitReason=10` (`LpcReply`); no marker was written. The bounded classifier is `CREATEPROCESSWITHTOKEN_CHILD_STALLED_IN_LPC_REPLY`. The internal Windows cause is not established. This remains a required failing gate.

### Linux isolated-worker pilot

The local Docker Desktop/WSL2 pilot used only an already-cached image pinned as `curlimages/curl@sha256:08e466006f0860e54fc299378de998935333e0e130a15f6f98482e9f8dab3058`. It independently observed non-root UID 65534, `NoNewPrivs=1`, zero effective capabilities, read-only rootfs, bounded tmpfs, `network=none`, TEST-NET denial, PID/memory/CPU/nofile limits, host-side synthetic bearer rejection, scoped request rejection, and clean recovery. Report SHA-256: `571f206d7fee0007ce51fb4f1ab6ffc66dd8d913db44bc1625d670987b273741`.

This is `VERIFIED_LOCAL_PILOT`, not production enforcement. The daemon was not rootless, and authenticated production invocation is `NOT_COVERED`.

## Independent test summary

- Unit suite: 176 tests, normal/repeat/Python `-O`, all passed locally.
- Gateway input/report mutants: 15 `KILLED`; zero `SURVIVED`, `NOT_APPLIED`, `CRASHED`, or `CONTROL_BROKEN`.
- Gateway physical source mutants: 16 `KILLED`; all had passing baselines and restored controls.
- Integrity physical mutants: 11 `KILLED`; all had passing baselines and restored controls.
- Historical PR #1 detached replay: portable chain and frozen integrity both exited 0; report SHA-256 `a7de0132bdba8397fee02e298cad70dd7cb4d160390df61b7a9fd3596cfadfd5`.
- Current local Windows native assessment: `PARTIAL`, never promoted to `VERIFIED`.

Exact commands and evidence boundaries are in `INDEPENDENT_REPLAY.md`; every non-final mutation run is preserved in `MUTATION_REPORT.md`.

## Gate decision

Production readiness is refused. Required next work is an independently reproducible restricted-token child-startup result on a supported Windows host, followed by the complete native campaign on that same boundary and a separate security review of authenticated production integration/provenance. Until then: **HOLD**.
