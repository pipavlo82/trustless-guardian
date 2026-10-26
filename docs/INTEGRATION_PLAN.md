# v02 read-only native probe

`tools/native_probe.py` validates exact source HEAD and clean tracked/untracked
state before invoking existing native interfaces. It does not rewrite upstream
repositories, copy native code into Guardian, replace canonicalization, or alter
ERC-8404's six-field receipt.

Pins remain ReceiptOS `f39ac3b289be6baef1140c53976d525d8eb45c8c`,
VECA `e2aca1a029203f1d5c73db2f8872b4240e793bfb`, and recompute-kit
`b4537d73bda4e4df73c4b105ee516a43c351ba02`. Live default HEAD retrieval matched
these pins during this pass. Source licensing remains in THIRD_PARTY_NOTICES.

Observed: the ReceiptOS verifyV2 fixture invocation cannot load the pinned
`@noble/curves` dependency in the read-only audit checkout (exit 1). VECA's actual
evaluate/admit invocation executes and returns REFUTED with unauthorized admission
in this unprepared native-verifier environment; this is not proof verification or
an upstream defect finding. Exact native outputs are preserved, not converted to
a generic success flag. recompute-kit's agent-action contract is source-audited;
its integration is not fabricated.

Full native integration is **NOT_COVERED**. Required next contract: externally
trusted native input bytes, executed pinned verifier/toolchain, retained native
status/scope/authority/assumptions, and an independently adequate mapping to the
exact Guardian actor/action/resource/policy/digest/expiry/nonce. Even then native
evidence must pass Guardian authorization before any broker action.

The following historical plan is preserved.

# Integration plan and native verdict preservation

`guardian/adapters.py` provides two versioned **research envelopes**:
`receiptos.verify.v2` and `veca.integration.v0`. It preserves exact native output
bytes and their SHA-256, source repository, full commit and interface identity.
It does not call a native verifier. Native re-verification is NOT_IMPLEMENTED,
Guardian authorization is UNVERIFIABLE and execution authority is always false.

This intentionally preserves VERIFIED / REFUTED / UNVERIFIABLE and richer native
ReceiptOS outcomes such as CANNOT_RECOMPUTE and INSUFFICIENT_EVIDENCE as original
bytes. No Boolean projection is substituted for those outcomes. Passing envelope
tests is not native receipt/proof verification.

| Existing component | Candidate use | Missing step before enforcement |
| --- | --- | --- |
| ReceiptOS `verifyV2()` | Strict admission, claim-surface comparison, independently selected context and native evidence | Execute pinned verifier with original inputs; bind every consumed claim dimension to Guardian policy |
| VECA `evaluate()` / `admit()` | Scenario coverage, scoped authorization and consumer recomputation | Explicit mapping from finite lab claim to a specific actor/action/resource; preserve missing links |
| Recompute-kit subject record | Agent-action pre/post subject commitments | Exact subject bytes, policy selection and relation to the actual OS operation |
| ERC-8404 RVR | Recompute claim/evidence/profile/result commitments | External action authorization and OS binding; Core remains unchanged |
| Semantic ABI / RSI / protected-relation fixtures | Separately declared expectations, observations, native outcomes and mutation witnesses | A versioned Guardian conformance profile; do not duplicate their engines |
| Semantic execution guard | Resource-side enforcement pattern | Windows adaptation is independent original code, not Solidity authorization reuse |
| Crystal / recompute-lens | Receipt integrity and inspection | Neither supplies Windows execution authority |

Before a real adapter can authorize, require exact actor, action, resource, scope,
policy version/digest, expiry, nonce and evidence preimages selected by the trusted
consumer. Recompute the native result, reject unsupported fields and preserve its
authority and evidence limitations. A verified receipt must never bypass the broker.

The current Guardian evidence is a local file precondition and host observation.
There is no real zkIE-to-ReceiptOS-to-Windows chain. Existing VECA research remains
PARTIAL_CHAIN_VERIFIED where its own reports say so; this experiment does not
upgrade it. ERC-8404 Core and ReceiptOS canonicalization profiles are unmodified.
