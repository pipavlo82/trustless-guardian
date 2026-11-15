# Guardian mutual IPC broker authentication v1

Local research, based on PR7 `2a40075a7f217e9c385cdfaf27c0267fa788d574`.
All historical PR7 files, reports, manifests and original Resonance core remain unchanged.
This additive successor must be invoked explicitly; old PR7 is not silently relabeled secure.

Protocol: `guardian.mutual-ipc-auth.v1`. Ed25519 signs the domain
`GUARDIAN-BROKER-AUTH-V1\0` followed by Guardian integer-only canonical JSON.
The signed envelope binds protocol, client-generated 256-bit session and challenge,
pipe channel, phase, exact request SHA256, expected broker/key/root identity,
issued/expiry timestamps and the complete response. Each phase is consumed once;
invalid responses terminate the session. A local monotonic 30-second deadline and
signed time window supplement fresh challenges. Time is a local-clock assumption.

The launcher independently supplies a read-only public trust file; the server
cannot select its own root. Missing, revoked, expired or malformed roots refuse.
Actual revocation distribution/rollback resistance and production key custody are
not established. The broker's private key never enters the agent runtime, argv,
environment or evidence. The lab creates ephemeral keys and passes one to the broker
through an anonymous stdin pipe; this is not a production key management service.

Both replies (synthetic observations and final HOLD/DENY) are authenticated inside
the actual zero-capability AppContainer. The old pipe ACL, impersonation, SID and
capability checks are retained through imported PR7 transport. First-instance/local-only
pipe flags add channel hygiene. The original core receives synthetic signals only.
No sensors, worker, Docker launch, real grant or action permission is introduced.
Success remains `HOLD_GUARDIAN_GRANT_REQUIRED`.

Cryptography uses the existing Guardian dependency lock: cryptography50.0.2/cffi2.1.1.
The private read-only runtime contains the corresponding verification library,
original canonical/errors modules and unchanged agent; package initializers are
empty to avoid unrelated JWT/SIWE imports. No global Python ACL or AppContainer
capabilities are widened. Runtime file hashes are recorded per native case.

Windows Python3.12 plus existing hash-locked Guardian dependencies are required.
Use a new output path for every run:

```text
python -B -m unittest discover -s research/guardian_mutual_ipc_v1/tests -v
python -O -B -m unittest discover -s research/guardian_mutual_ipc_v1/tests -v
python -B research/guardian_mutual_ipc_v1/native.py --out <new-outside-directory>
python -B research/guardian_mutual_ipc_v1/verify_evidence.py --evidence <directory> --trust-sha256 <independently-recorded-trust.json-hash>
python -B research/guardian_mutual_ipc_v1/mutations.py --out <new-outside-directory>
python -B tools/integrity_v5.py --policy-sha256 <independent-v5-policy-pin>
```

`native.py` records OBSERVED, not PASS. `verify_evidence.py` independently checks
all26 cases, native process exits/OS identity and cryptographic transcripts against
the independently supplied root digest. Evidence files are local observations, not
signed remote OS attestations. Physical mutation grading requires a distinguishing
assertion failure, healthy positive and restored bytes; harness crashes are non-kills.

No workflow is rewritten. Historical v4 correctly rejects newly added paths; use v5
for this additive candidate and v4 on exact PR7. Any future publication needs explicit
CI routing review rather than weakening old integrity gates. All implementation
reports and exact execution logs live outside the repository.
