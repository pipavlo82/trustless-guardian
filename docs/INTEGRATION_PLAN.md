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
