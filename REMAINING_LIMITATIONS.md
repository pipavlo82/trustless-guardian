# Remaining limitations

## Required blockers

1. **Production identity and provenance — `NOT_COVERED`.** Synthetic token booleans do not prove JWT signature, issuer, audience, expiry, nonce, wallet control, registry state, MCP bearer validation, or event origin. Reports are deterministically recomputable but unauthenticated.
2. **Production Linux isolation — `NOT_COVERED`.** Rootless daemon mode, production tool invocation, real secrets handling, and production network policy were not exercised. Only a local synthetic non-root/zero-capability container was validated.

## Evidence boundaries

- Synthetic metrics do not establish real-world detection accuracy and must not be used as a production score.
- Detection is triage only. A finding cannot authorize an action, and absence of a finding cannot bypass authorization.
- The new held-out corpus is separate in code and construction from the functional trace, but it is still authored synthetic data, not an externally governed dataset.
- GitHub-hosted CI is not an independent second machine or an attestation service.
- Pinned action commit SHAs reduce mutability but do not prove action provenance or eliminate upstream compromise risk.
- The layered-integrity policy needs an external pin from the exact workflow/commit. Self-authentication of an untrusted checkout is impossible; GitHub branch identity is not cryptographic release attestation.
- The historical v0.7 tree remains frozen with its original HOLD semantics and historical mutation failures.
- Hosted Windows Server 2022 now verifies the required restricted-token startup and the complete 41/15 native campaigns, but a GitHub-hosted runner is still one provider-controlled test boundary, not a separately controlled second machine or release attestation.
- No Vértice infrastructure, live incident evidence, real credentials, client NDA data, third-party service, or live deployment was accessed.

## Next necessary review

Repeat the exact Windows candidate on a separately controlled supported host, preserving the pre-resume token proof, private-desktop restrictions, 41-case v0.2 campaign, and 15-scenario v0.4 recovery campaign. This is an independent-review requirement, not a substitute for the already passing hosted gate.

Separately, design and review a production integration that performs real JWT/MCP bearer validation, wallet/owner/resource binding, authenticated evidence provenance, secret redaction, fail-closed recovery, and explicit egress policy. Neither workstream may reuse synthetic `ALLOW` as proof of production authorization.

Final verdict: **HOLD**.
