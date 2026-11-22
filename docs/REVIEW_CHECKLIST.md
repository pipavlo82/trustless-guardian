# Independent review checklist

- Detach at the exact research commit; verify the inventory before execution.
- Inspect source pins, licenses and the narrowly stated local-file policy.
- Run from a normal Windows token on disposable NTFS storage; never elevate to
  hide an unsupported environment.
- Confirm child process exit, AppContainer SID, low integrity, zero capabilities
  and writable scratch before accepting a direct-access denial.
- Confirm allowed bytes by a host read, not only by the broker's record.
- Confirm every denied request and unavailable-component case leaves bytes unchanged.
- Inspect the ACL mutation's actual successful unauthorized write, then byte-exact
  source restoration and restored denial.
- Check mutation positive controls, raw exit codes and crash classification.
- Compare semantic outputs across normal/repeat/optimized and fresh-checkout runs.
- Independently inspect broker identity, file-handle and nonce transaction assumptions.
- Verify both v02 AppContainer tokens and the distinction from separate Windows accounts.
- Reproduce the isolated caller-token and server-PID controls and the inheritable
  host-handle refusal with its successful host-write positive control.
- Inspect real post-crash bytes and durable journal states; do not infer atomicity.
- Audit the exact hosted token and process-creation failure separately from local
  success. An unavailable enforcement campaign is not a passing CI profile.
- Audit evidence trust anchors, canonicalization and exact authorization scope.
- Do not treat research envelopes as working ReceiptOS/VECA integrations.
- Keep the PR in Draft until findings and unsupported production obligations are reviewed.
