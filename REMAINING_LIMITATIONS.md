# Remaining limitations

## Required blockers

1. **Windows restricted-token child startup — `NOT_COVERED`.** Hosted Windows Server 2022 creates and resumes the reduced-token child but does not observe user-code startup; hosted v0.2/v0.4 campaigns are consequently control-broken and their core properties remain `NOT_COVERED`. Local Windows 11 testing was not elevated and cannot exercise the same reduction path. The observed hosted `LpcReply` wait is a symptom classification, not an internal root-cause proof.
2. **Production identity and provenance — `NOT_COVERED`.** Synthetic token booleans do not prove JWT signature, issuer, audience, expiry, nonce, wallet control, registry state, MCP bearer validation, or event origin. Reports are deterministically recomputable but unauthenticated.
3. **Production Linux isolation — `NOT_COVERED`.** Rootless daemon mode, production tool invocation, real secrets handling, and production network policy were not exercised. Only a local synthetic non-root/zero-capability container was validated.

## Evidence boundaries

- Synthetic metrics do not establish real-world detection accuracy and must not be used as a production score.
- Detection is triage only. A finding cannot authorize an action, and absence of a finding cannot bypass authorization.
- The new held-out corpus is separate in code and construction from the functional trace, but it is still authored synthetic data, not an externally governed dataset.
- GitHub-hosted CI is not an independent second machine or an attestation service.
- Pinned action commit SHAs reduce mutability but do not prove action provenance or eliminate upstream compromise risk.
- The layered-integrity policy needs an external pin from the exact workflow/commit. Self-authentication of an untrusted checkout is impossible; GitHub branch identity is not cryptographic release attestation.
- The historical v0.7 tree remains frozen with its original HOLD semantics and historical mutation failures.
- No Vértice infrastructure, live incident evidence, real credentials, client NDA data, third-party service, or live deployment was accessed.

## Next necessary review

Run the exact candidate on a supported, independently controlled Windows host where the parent is elevated and the reduced-token launch path can be observed end to end. Diagnose the stall with Windows-native tracing without relaxing token restrictions. If and only if startup succeeds, rerun AppContainer identity, pipe authentication, broker/file bypass, execution, and crash recovery on that same host.

Separately, design and review a production integration that performs real JWT/MCP bearer validation, wallet/owner/resource binding, authenticated evidence provenance, secret redaction, fail-closed recovery, and explicit egress policy. Neither workstream may reuse synthetic `ALLOW` as proof of production authorization.

Final verdict: **HOLD**.
