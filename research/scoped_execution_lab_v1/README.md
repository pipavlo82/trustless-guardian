# Scoped execution laboratory v1

Opt-in local composition based on PR8 `299487d7d7884b2cb2adc7df86b6485ee18daba7`.
This directory is not called by any historical service, CI route, or IPC client.

A genuine zero-capability Windows AppContainer sends the unchanged two-phase
proposal. The original broker verifies its pipe token/SID and the client verifies
both Ed25519 responses. Both original participants still record HOLD/no execution.
Only the new trusted laboratory broker supervisor may then apply a separate,
explicit short-lived lab policy to the directly returned live request. It issues
the existing scoped v2 grant and atomically reserves it in the existing SQLite
admission store before creating a disposable, non-root, network-disabled worker.
The job hashes bounded canonical request bytes and writes a temporary marker
inside its own tmpfs. No external application or protected customer file changes.

The client is NOT informed that an action completed. A signed host observation and
separate Node verifier provide a reviewer-facing result. This is not a new IPC
protocol, production execution API, JWT/SIWE bridge, or autonomous agent service.
The trusted supervisor is not reachable by the AppContainer except through the
original SID-checked pipe. Do not expose `admit_live_result` as an RPC or use saved
JSON as current authority: a Python dict cannot authenticate its origin.

## Boundaries

- Host OS, Docker daemon, lab supervisor and ephemeral signing keys are trusted.
- Agent is zero-capability AppContainer and cannot select policy, paths, images,
  arbitrary commands, host environment, trust roots or keys.
- Worker image and executable hashes are pinned. No shell exists in the scratch
  image. Fixed limits: 64 MiB RAM+swap, 0.5 CPU, 16 PIDs, 64 file descriptors,
  8 MiB scratch, no network, read-only root/input, all capabilities dropped,
  no-new-privileges; Docker default seccomp verified by the worker.
- Original scoped grant verification and durable replay gates remain unchanged.
- New executor kills/removes the named container on deadline, rather than killing
  only the Docker CLI. Resource output monitoring is polling, not a hard zero-
  overshoot byte quota. Fixed worker output is bounded by source.
- COMMITTED in legacy receipts means a process completed, not successful action.
  New verifier additionally requires exit zero, exact recomputed stdout, no stderr.
- New verifier uses Node crypto, not the Python verifier implementation. This is
  separate-implementation checking by the same Codex executor, NOT human audit.
- OS observations are crosschecked but not hardware/remote attestation. Signature
  validation alone establishes neither process identity nor actual execution.
- Lab public keys are not production roots. Historical capture validity does not
  authorize a present action. No exactly-once/crash-recovery guarantee is made.

## Replay

Use Windows Python 3.12 with the unchanged hash-locked requirements-auth-v1.txt;
native packager requires cryptography 50.0.2 and cffi 2.1.1. Node 22 and Docker
Desktop Linux engine are required. Public fixture credentials exist only in RAM.
No keys, daemon sockets or private source directories are mounted into worker.

```powershell
python -B -m unittest research.scoped_execution_lab_v1.test_lab -v
python -B -O -m unittest research.scoped_execution_lab_v1.test_lab -v
python -B -m research.scoped_execution_lab_v1.mutations --out <NEW_DIRECTORY>
python -B research/scoped_execution_lab_v1/native_run.py --out <NEW_DIRECTORY>
node research/scoped_execution_lab_v1/verify_native.mjs <NATIVE_DIRECTORY> <TRUST_FILE_SHA256>
python -B research/scoped_execution_lab_v1/integrity.py --pin <SOURCE_SHA256_JSON_DIGEST>
```

Image must match `image.json` exactly. Load the provided local image archive and
verify the archive digest before replay. The binary was built with the recorded
Ubuntu compiler/libcrypto; rebuilding with another toolchain may change hashes.
Do not silently update image/worker pins to force replay. Old full-tree integrity
v8 intentionally refuses this additive experiment. Replay v8 at its frozen base;
the explicit new inventory checks all 386 inherited files plus laboratory files.
No workflow has been weakened or rerouted.

The external reviewer package contains observed results, failures, root pins,
exact candidate commit, Windows SID/PID/ACL evidence and integration prerequisites.
Production remains HOLD. Merge decisions require review of the actual stack and
updated base, not merely these local test results.
