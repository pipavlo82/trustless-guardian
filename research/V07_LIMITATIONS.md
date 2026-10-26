# v0.7 limitations and review boundary

- Finite synthetic-file laboratory, not production security or arbitrary agent containment.
- Only actual Hermes orchestration/tool execution is AppContainer-confined. The
  inference relay, remote provider, host observer and provisioner are trusted.
- Distinct agent/broker AppContainers share a base Windows user. Host/admin/SYSTEM/
  kernel compromise and malicious host evidence fabrication are outside the model.
- The private Hermes inference-client hooks remain version-pinned. Public plugin
  registration alone does not establish compatibility of the complete transport.
- An exact copied dependency inventory is required; independent bootstrap and
  general Hermes/Codex/Cursor/Grok compatibility remain NOT_COVERED.
- The historical v0.6 repeat failed at POLICY_CHANGE because generated content
  exceeded its strict 128-byte bound; normal and optimized passed. This failure
  remains preserved and prevents an all-historical-live-regressions-green claim.
- The live model may refuse or select an unexpected tool. Such a run fails visibly;
  deterministic controls do not repair or replace its live evidence.
- The v1 transport/strict schema is not permission. Authorization still requires
  the unchanged broker's independently selected policy and actual pipe identity.
- Four physical boundary mutants are observed, not exhaustive mutation coverage.
  Historical v0.6 CONTROL_BROKEN and v0.3 SURVIVED classifications remain immutable.
- The fixed oracle checks consistency and actual local bytes/tokens. It cannot
  establish honest host observation or correctness of arbitrary policy designs.
- SQLite and filesystem updates are not atomic together. PREPARED/RECOVERY_REQUIRED
  can remain after changed bytes. No exactly-once execution, automatic ambiguous
  retry or inference of non-execution from equal bytes is supported.
- Hosted Windows enforcement remains CI_BLOCKED. Portable green is not an OS result.
- Cross-machine replay and independent human certification remain NOT_COVERED.
- ReceiptOS/VECA/recompute-kit interfaces were inspected read-only. Export is a
  proposed contract; native execution integration remains NOT_COVERED. No upstream
  receipt, VERIFIED flag or inference proof automatically authorizes a write.
- Broader external evidence chain remains PARTIAL_CHAIN_VERIFIED. No production
  release, repository merge, deployment or frozen ERC-8404 change is made.

Recommendation: **ITERATE** for a narrowly scoped developer preview and independent
review; **HOLD** for production use. Next work is public Hermes transport support,
independent dependency bootstrap and a second safely provisioned Windows replay.
