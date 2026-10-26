# Source audit, 2026-10-24

This is a source inspection and selected local replay, not certification of the
upstream projects. All ten repositories were cloned separately, their Git trees,
license files, implementation interfaces and relevant tests inspected. Their
tracked source remained unchanged. Exact selected Git-blob SHA-256 inventories
are in [source-lock.json](source-lock.json). No upstream source was vendored.

| Repository | Exact inspected commit | License boundary |
| --- | --- | --- |
| [recompute-kit](https://github.com/trustless-ai/recompute-kit/tree/b4537d73bda4e4df73c4b105ee516a43c351ba02) | `b4537d73bda4e4df73c4b105ee516a43c351ba02` | CC0-1.0 |
| [VECA](https://github.com/trustless-ai/verifiable-execution-claim-authorization/tree/e2aca1a029203f1d5c73db2f8872b4240e793bfb) | `e2aca1a029203f1d5c73db2f8872b4240e793bfb` | MIT; embedded third-party history retains its notices |
| [recompute-lens](https://github.com/trustless-ai/recompute-lens/tree/61f7392f1c4758231517b22ba06ab608dedbae02) | `61f7392f1c4758231517b22ba06ab608dedbae02` | CC0-1.0 |
| [semantic-abi](https://github.com/trustless-ai/semantic-abi/tree/d15c666dfccff17f7350fe97d2fc7b71cb2cbaee) | `d15c666dfccff17f7350fe97d2fc7b71cb2cbaee` | Apache-2.0 code; schema CC0-1.0 |
| [receiptos-verify](https://github.com/pipavlo82/receiptos-verify/tree/f39ac3b289be6baef1140c53976d525d8eb45c8c) | `f39ac3b289be6baef1140c53976d525d8eb45c8c` | Apache-2.0 original material; THIRD_PARTY_NOTICES.md governs vendored pieces |
| [crystal-receipt](https://github.com/pipavlo82/crystal-receipt/tree/45b46bf7df3a60b32583291f577a36bf19d22f00) | `45b46bf7df3a60b32583291f577a36bf19d22f00` | Apache-2.0 original material; third-party applications excluded from relicensing |
| [recomputable-verification-receipts](https://github.com/pipavlo82/recomputable-verification-receipts/tree/9dd36e882dd372f264b77b179130948aa5adcbde) | `9dd36e882dd372f264b77b179130948aa5adcbde` | Apache-2.0 original material |
| [semantic-execution-guard](https://github.com/pipavlo82/semantic-execution-guard/tree/18f595b537017e5ff7b9074366c3065e877488f9) | `18f595b537017e5ff7b9074366c3065e877488f9` | Mixed: explicit Apache grant for listed Pavlo consumer files; Federico guard lane MIT; dependency grants separate |
| [relational-security-invariants](https://github.com/pipavlo82/relational-security-invariants/tree/3d3038f90c3dd98e79f948398167c5cc3ef2fdd8) | `3d3038f90c3dd98e79f948398167c5cc3ef2fdd8` | Apache-2.0 + NOTICE; captured external code retains original terms |
| [protected-relation-fixtures](https://github.com/pipavlo82/protected-relation-fixtures/tree/fac26d2e8346aeab08194343b78c345d235c6935) | `fac26d2e8346aeab08194343b78c345d235c6935` | MIT; captured external sources retain their licenses |

The semantic-execution-guard consumer retains historical UNLICENSED source headers,
but its current `LICENSING.md` explicitly supersedes those pending markers for
the identified first-party consumer files. The MIT contributed guard is not
relicensed by that grant. Guardian imports none of these files.

## Implementation findings

**ReceiptOS Verify.** `src/core/verify-v2.mjs:verifyV2(requestInput,bundleInput)`
performs admission, integrity/authenticity checks, native recomputation and
projection. `src/core/claim-surface.mjs` compares ten claim-surface dimensions;
it does not infer a hierarchy from scope names. Independently selected context
must not be reconstructed solely from the caller's signed bundle. Native results
and product projections have richer statuses than a Boolean. The guarantee-boundary
tests reject unknown guarantee fields even when authentication remains valid.
Neither a verified signature nor a valid result is Windows write authority.

**VECA.** `src/integration/engine.py:evaluate()` and `admit()` bind scenario,
canonical contract, claim type, evidence and scope. Admission recomputes instead
of trusting a mutable result. `src/v4_1/model.py` separates O14 key identity from
real-world controller independence. Its finite lab and partial-chain assumptions
cannot be promoted to arbitrary agent execution. Guardian has not replayed the
entire VECA native-proof chain in this task.

**Recompute-kit.** The inspected agent-action subject-record adapter under
`research/chain-neutral-receipt-anchor-proof-v0/` separates pre-action commitment,
post-action record, trusted policy context, signed identity and anchor assurance.
These supply candidate subject bindings, not an OS capability. Existing graders
and mutation infrastructure remain external components, not code to duplicate.

**RVR / ERC-8404.** `conformance/rvr-v0/adapter.py` independently recomputes claim,
evidence-set, verification-profile and result commitments. Its SHA256_EQUALS
profile distinguishes unavailable evidence from digest mismatch. Receipt
reproduction does not authorize an OS operation. The pinned specification,
schema, profile and conformance sources remain unchanged; Guardian adds no Core
requirement and claims no new normative ERC conformance.

**Semantic ABI.** `runner/src/evaluate.mjs` separates expected relation, observed
relation and backend conformance. Unavailability is CANNOT_CHECK, not a pass.
Its isolated four-test evaluator suite was replayed successfully. Guardian keeps
the same distinction between a correct denial, authorization and execution.

**RSI.** `runner/expectation_contract.py` independently predicts expectations,
binds fixture sets, admits them atomically and rejects profile/expectation drift.
`rsi/run.py` distinguishes PASS, FAIL and RUNNER_ERROR. A local run could not import
the pinned cryptography dependency: this is an infrastructure limitation, not
an RSI conformance failure. No RSI runtime result is claimed.

**Protected relation fixtures.** The external adapter contract binds request,
challenge/profile digests, evaluator output and invocation identity; it preserves
UNVERIFIABLE and process errors. All 34 selected adapter-contract tests passed
after fetching required tag `v0` (`98ccba804c725777e155ad2f1a07bae49754376b`).
The original shallow-clone attempt had one tag-resolution error and is preserved.

**Semantic execution guard.** The inspected Solidity resource target restricts
its caller and asset; action identifiers are not inherently nonces. The contributed
guard establishes a fresh bound price, not successful trade/payment execution.
This supports the resource-side enforcement architecture, but no Solidity code
or blockchain guarantee is reused in the Windows pilot. Foundry was not executed.

**Crystal and recompute-lens.** Crystal's receipt-root verifier recomputes a
canonical hash after removing the top-level anchor. Lens performs client-side
recomputation and explicitly distinguishes absent comparison targets from matches.
Neither verifies all facts asserted by an input record. Their canonicalization
is not silently replaced by Guardian's own JSON encoding. Browser/build suites
were not run in this task.

## Executed source checks

Raw commands/stdout/stderr are preserved in the evidence archive under source-tests.
These are separate from Guardian's own counts.

| Check | Observed result |
| --- | --- |
| Semantic ABI `node --test runner/test/evaluate.test.mjs` | 4 tests passed |
| RVR `python -B conformance/rvr-v0/adapter.py --check` | RVR_V0_CONFORMANCE_PASS; 13 canonical-byte and 7 dependency-resolution vectors; native report contains 6 semantic controls |
| PRF adapter-contract unittest subset | 34 passed after required tag fetch; original 1 infrastructure error retained |
| RSI `python -B -m rsi.run` | Import failure: missing `cryptography`; NOT_COVERED |
| Original local Guardian prototype | 4 preliminary policy tests passed; three original source hashes unchanged |
| ReceiptOS, VECA full chain, kit full suite, lens, Crystal, Solidity guard suites | Source/test inspection only; not executed here |

## Windows primary-source basis

The implementation uses documented per-user
[AppContainer creation](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile),
[AppContainer access isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation),
[process security attributes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
and [OS token inspection](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation).
Documentation establishes API semantics; the recorded processes and byte witnesses
establish only the finite observed local behavior. This is not a scientific novelty claim.
