# guardian.evidence-export.v1 — proposed external interface

DESIGN ONLY; ReceiptOS/VECA/recompute-kit native integration NOT_COVERED.
No upstream canonicalization profile or six-field ERC-8404 receipt changes.

A carrier must preserve schema/version, exact Guardian source SHA, population,
request/policy preimages and digests, native broker result, before/after resource
identities/byte digests, OS observations, native verifier report and source-pinned
upstream report including all status axes/assumptions. It requires an explicit
mapping_profile and independently selected subject/action/scope/authority/dependency
contract. Missing native artifacts remain missing.

Export is not bearer permission. Importers must execute the selected native verifier,
compare consumed fields, retain unconsumed fields, recompute the consumer contract
commitment and reauthorize at execution time. Local observation is not external attestation.

Read-only audit pins matched remote HEADs:

- ReceiptOS f39ac3b289be6baef1140c53976d525d8eb45c8c: verifyV2 and claim-surface comparison.
- VECA e2aca1a029203f1d5c73db2f8872b4240e793bfb: evaluate/admit, finite laboratory scope.
- recompute-kit b4537d73bda4e4df73c4b105ee516a43c351ba02: agent-action subject record.

See [file hashes](../research/V07_SOURCE_AUDIT.json) and
[evidence-to-action obligations](EVIDENCE_TO_ACTION_CONTRACT.md).
No native verifier was executed by this preview. A new reviewed semantic mapping
and behavioral controls are required before these artifacts can inform a Guardian
file replacement. Broader chain remains PARTIAL_CHAIN_VERIFIED.
