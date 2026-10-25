# v0.6 limits

- This is one non-elevated Windows 11 Home build 26200 host. A second physical
  Windows environment and independent human review remain **NOT_COVERED**.
- The host user, provisioner, runtime copies, broker code and inference relay are
  trusted. Agent and broker have different AppContainer SIDs but the same base
  Windows user. This is not a separate service account or administrator boundary.
- Native Hermes Nous authentication failed with re-login required. The tested
  path is an experimental Codex CLI inference bridge. Cursor and Grok are only
  identified installations; neither is a verified agent integration.
- No credentials are given to the confined process. The trusted relay uses the
  existing ChatGPT login and quota. The model is remote; agent orchestration and
  tool dispatch are confined locally. This is not offline/local-model inference.
- The agent has two narrowly scoped tools and a one-process job. Arbitrary
  coding tools, terminals, package managers, network capabilities and third-party
  plugins are not demonstrated. The result cannot be generalized to unrestricted
  Hermes, Codex, Cursor, Grok, Claude or OpenClaw installations.
- Raw provider transcripts and OS observations rely on the honest host. A
  consistent evidence archive is not proof against host/relay fabrication.
  Public path-redacted derivatives retain separate original/published digests;
  they are not byte-identical copies of private raw logs.
- Model responses are nondeterministic. Repeated equality concerns declared
  semantic checks, not prose, timings, SIDs, paths or raw provider output.
- NTFS write/delete/rename/extended-path tests cover the declared synthetic
  resource. They do not establish prevention of all possible Windows exploits,
  side channels, arbitrary resource classes or hostile privileged code.
- File writes and SQLite commits are not one transaction. PREPARED plus changed
  bytes is ambiguous. There is no exactly-once or automatic retry guarantee.
- Hosted Windows enforcement remains **CI_BLOCKED** when a safe non-elevated
  Python child cannot start. Portable CI and local success are different claims.
  No persistent runner, account, privilege or system policy was provisioned.
- Historical timing-sensitive regression failures and mutation survivors remain
  historical evidence. A passing v0.6 profile does not turn every old run green.
- ReceiptOS, VECA and recompute-kit native verification remain **NOT_COVERED**
  for action admission. No receipt is treated as execution permission. ERC-8404
  Core and all upstream repositories remain unchanged.

Research may continue with independent replay and a narrower provider transport
audit. Production deployment, security certification and unrestricted agent
integration remain on hold.
