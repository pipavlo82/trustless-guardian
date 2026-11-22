# guardian.evidence-to-action.v0 — proposed external adapter contract

**DESIGN ONLY / native execution admission NOT_COVERED.** This document grants no
permission and defines no additional ERC-8404 field. No upstream code is copied or
modified. Existing canonicalization profiles and native verdicts retain meaning.

## Independently selected consumer context

The caller selecting policy is the trusted resource consumer/provisioner. An
untrusted agent cannot choose a weaker policy, trust root, verifier or filesystem
path through its request. Bind exact canonical Guardian policy bytes and SHA-256,
policy version, supported native profile/source commit, accepted authorities,
required obligations/dependencies, verification instant and finite action mapping.
Contract adequacy and authority selection remain explicit trusted assumptions.

## Versioned carrier (not a bearer credential)

| Required item | Admission obligation |
| --- | --- |
| schema / mapping_profile / source_commit | Exact supported versions; no name-based compatibility inference |
| native_input_bytes / evidence_bytes / dependencies | Preserve original bytes, native canonicalization ID and independently recomputed digests; unavailable material remains unavailable |
| native_result_bytes / verifier_identity | Execute pinned native verification against the consumer's input and policy; compare result, retain all native status axes and reasons |
| native_subject / claim / scope / authority / assumptions | Explicit lossless extraction; every consumed dimension must have a defined semantic mapping |
| action_request_bytes | Exact Guardian actor/action/resource/scope/content/precondition/version/expiry/nonce; OS identity is supplied by IPC, not this carrier |
| consumer_contract_bytes / SHA-256 | Consumer-selected preimage must match the independently recomputed commitment; a digest without bytes is insufficient |
| coverage / missing / unconsumed | Independently declared requirements; no unknown or silently unconsumed field may acquire authority |
| execution_time_context | Recheck policy, resource identity/state, expiry and nonce while broker holds handles; earlier verification is not a capability |

No generic conversion of `VERIFIED` to ALLOW exists. Guardian's current broker
accepts only its exact local-file action envelope; an adapter cannot add a new
evidence field to that schema silently. Implementing this proposal requires a new
explicit supported profile and negative/mutation tests before it can authorize.

## Read-only source audit (live HEADs matched pins)

| Component / pin | Actual interface | Permitted reuse and missing relation |
| --- | --- | --- |
| [ReceiptOS](https://github.com/pipavlo82/receiptos-verify/tree/f39ac3b289be6baef1140c53976d525d8eb45c8c), Apache-2.0 | src/core/verify-v2.mjs `verifyV2(request,bundle)`; src/core/claim-surface.mjs `compareClaimSurfaces` | Exact caller-selected surfaces, authenticated evidence and native recomputation. Preserve overall and layer statuses including CONTRADICTED / INSUFFICIENT_EVIDENCE / CANNOT_RECOMPUTE. Supplied traces are not external execution provenance |
| [VECA](https://github.com/trustless-ai/verifiable-execution-claim-authorization/tree/e2aca1a029203f1d5c73db2f8872b4240e793bfb), MIT | src/integration/engine.py `evaluate(case)` / `admit(presented,case)` | Independently recomputed scoped admission for LAB_REPLAY_AND_REVIEWED_PROOF_IDENTITY. This claim does not authorize a Windows write or payment |
| [recompute-kit](https://github.com/trustless-ai/recompute-kit/tree/b4537d73bda4e4df73c4b105ee516a43c351ba02), CC0-1.0 | research/chain-neutral-receipt-anchor-proof-v0/adapter.mjs `admitSubject(raw)` / `evaluate(input,context)` | agent-action.subject-record.v0 commits exact supplied bytes; metadata has no authority. Optional inclusion proof is a separate object. Neither proves actual execution |

Exact inspected file SHA-256 values and clean-worktree/read-only Git observations
are preserved in the v03 preflight archive's native-source-audit.json. Source
inspection is not native execution. The v02 dependency/proof-toolchain limitations
are preserved; no new successful native integration is claimed in v03.

## Required executable controls before implementation is accepted

Preserve native REFUTED and UNVERIFIABLE with positive receipt integrity; refuse
wrong actor/subject/action/scope/authority/policy, missing dependency/preimage,
unconsumed fields, stale verdict, mutable authorization flag, altered native output,
and valid hash-only proof offered as execution evidence. Re-run after a policy or
resource change. Every mapping guard needs a physical mutation and actual host
resource observation. A native verifier crash is dependency failure, not a semantic
negative or authorization. Broker access must never be delegated to native code.

Verification != authorization != enforcement != evidence of execution. The broader
VECA chain remains PARTIAL_CHAIN_VERIFIED; Guardian does not promote it.
