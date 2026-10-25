# Guardian v0.5 demonstration

**Real-agent integration: NOT_COVERED.** This demo launches the actual installed
Codex executable under a measured AppContainer token. The recorded CLI startup
succeeds, but the local provider is unavailable before any model response or
tool call. The ALLOW/DENY/BYPASS demonstration uses explicitly labelled scripted
clients and real Windows enforcement; it does not pretend they are AI agents.

## Prerequisites and safe replay

Use an already authorized **non-elevated Windows x64** account, NTFS, Python
3.12+, Git, and optionally the already installed native Codex CLI. No cloud
credential is required or copied. Do not run as administrator. See
[Windows protocol](../docs/WINDOWS_REPLAY_PROTOCOL.md).

```powershell
git clone https://github.com/pipavlo82/trustless-guardian.git guardian-replay
cd guardian-replay
git checkout --detach <REVIEWED_V05_SHA>
python -B tools/prepare.py
python -B demo/run_demo.py --out build/demo
python -B demo/verify_demo.py --files build/demo/snapshot-paths.json --out build/demo-post-runtime.json
python -B tools/validate_v05.py --out build/v05
python -B tools/validate_v04.py --out build/history
python -B tools/integrity.py
```

Use an exact reviewed commit from the PR/report, not a moving branch for a
reproduction. Each output directory must be new. `prepare.py` retrieves only
the SHA-pinned embedded Python distribution. The demo copies the local Codex
binary into an RX laboratory directory; it does not distribute that binary.

`--controls-only` omits the runtime probe explicitly. `--codex <native.exe>`
selects a trusted installed binary and records its SHA-256. The default exit 0
means **laboratory controls passed**, never that the real-agent mission passed.
Use `--require-real-agent` to require that mission: the present implementation
returns exit **3** (`NOT_COVERED`). Portable CI also cannot certify enforcement.

## What is observed

`ALLOW -> DENY -> BYPASS -> VERIFY`

- ALLOW: a proposal-only tool envelope reaches the native named-pipe broker;
  the broker authenticates its actual client and writes exact synthetic bytes.
- DENY: a request naming the protected configuration is refused. Files remain
  unchanged, including the broker's source resource.
- BYPASS: six direct native attempts (write, delete, rename, extended Win32 path,
  protected-config write, synthetic-secret read) return Windows error 5. A
  separate scratch write succeeds in each process. Host snapshots follow each.
- POLICY CHANGE: the trusted provisioner removes the actor from a new canonical
  policy, pins its bytes, and the formerly allowed action is refused.
- RECOVERY: an ordinary exception is injected **after a real write**. The broker
  returns `UNVERIFIABLE / RECOVERY_REQUIRED`, with retry prohibited. Its durable
  row remains `PREPARED` before reconciliation; no automatic retry is performed.
- VERIFY: a separate process reads exact bytes, native file identities and
  actual process tokens; it recomputes policy/request/receipt commitments without
  importing Guardian broker, policy, IPC or recovery modules.

All files, secrets and actions are synthetic. The agent project and home are
writable, protected resources are not, and the broker has a distinct package
SID under the same base user. ACL changes occur only in new `guardian-lab-*`
directories under ignored `build/`. No persistent account or security-setting
change is needed. AppContainer profiles are removed on normal completion;
laboratory files remain for inspection. Abnormal host termination may require
careful manual cleanup of those identified disposable profiles/directories.

This observation-heavy demo uses a versioned **8-second lab I/O deadline** and
40-second process limit. The historical IPC tests retain their original timing.
Lost responses remain failures/ambiguities; operations are never auto-retried.

See [integration status](../docs/REAL_AGENT_INTEGRATION.md),
[security results](../research/V05_SECURITY_RESULTS.md),
[mutation report](../research/V05_MUTATION_REPORT.md), and
[limitations](../research/V05_LIMITATIONS.md).
