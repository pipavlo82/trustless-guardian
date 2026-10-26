# Trustless Guardian developer preview v0.7

**Experimental local Windows laboratory. ITERATE; no production release.**
Verification != authorization != enforcement != evidence of execution.

The preview exposes one finite operation: replace a synthetic UTF-8 file under a
trusted, independently provisioned policy. It uses the unchanged Guardian broker,
authenticated named pipes, NTFS ACLs, separate AppContainer principals and a
separate native observer. It is not a general file broker or arbitrary agent sandbox.

## Quickstart

Use a non-elevated Windows x64 session and Python 3.12.10. Start from a clean
checkout of the exact reviewed research commit. Do not use personal resources.

```powershell
python -B tools/prepare.py
python -B demo/developer-preview/run.py --mode deterministic --out build/preview-offline
```

This is an explicitly **DETERMINISTIC_OS_CONTROL** population. It runs real Windows
operations, but does not infer, emulate or certify an AI model. The first command
fetches only the official SHA-pinned embedded Python runtime. Subsequent offline
runs need no provider or Hermes installation.

Live prerequisites: Hermes source f7c79efbac19ae18e8dee7c79a4e4c0935299b5f,
version 0.20.6, Python 3.11.16 and the exact preserved 14,114-file runtime inventory;
native Codex CLI 0.162.0-alpha.17.2 with the pinned image and an existing authorized
ChatGPT login. The relay requests gpt-6-luna and consumes existing account inference
allowance. No subscription or credential is created/copied. Provider availability
and model behavior are external prerequisites. See [compatibility](HERMES_COMPATIBILITY.md).

```powershell
python -B demo/real-agent/prepare.py --source "$env:LOCALAPPDATA/hermes/hermes-agent" --out build/guardian-lab-hermes-runtime
python -B demo/developer-preview/run.py --mode live --runtime build/guardian-lab-hermes-runtime --out build/preview-live
```

Each demo command displays **ALLOW → DENY → BYPASS → POLICY_CHANGE → RECOVERY → VERIFY**.
Use a new output directory for each run. Do not run two live demos against the same
copied runtime concurrently. No current-user Hermes/Codex profiles enter the agent.
Only newly created disposable resources receive ACL changes.

## What success means

| Stage | Required observation |
| --- | --- |
| ALLOW | Exact approved bytes, authenticated pipe, committed receipt |
| DENY | Wrong-resource refusal and unchanged protected bytes |
| BYPASS | Real write/delete/rename/extended-path attempts denied; writable scratch |
| POLICY_CHANGE | Trusted provisioner revokes actor permission; broker refuses |
| RECOVERY | Actual post-write fault; changed bytes, PREPARED, UNVERIFIABLE/RECOVERY_REQUIRED; no retry |
| VERIFY | Separate stdlib/native oracle checks tokens, bytes, model/tool or frozen-vector provenance and v1 bindings |

A live model refusal, missing tool call, malformed response, absent runtime,
IPC failure or timeout exits nonzero and records NOT_COVERED. There is no fallback
from live inference to deterministic input. Frozen vectors never enter the live
model's context or determine its answer.

## Full validation

```powershell
python -B tools/validate_v07.py --runtime build/guardian-lab-hermes-runtime --out build/validation-v07
python -B tools/validate_v07.py --portable --out build/portable-v07
python -B tools/validate_v07.py --offline --out build/offline-v07
python -B tools/validate_v04.py --no-mutations --out build/historical-v04
python -B tools/validate_v05.py --no-mutations --out build/historical-v05
python -B tools/validate_v06.py --runtime build/guardian-lab-hermes-runtime --out build/historical-v06
```

The v07 runner records normal/repeat/-O independently for both populations and
physical deterministic mutants. Portable captured-evidence tamper controls cannot
establish current Windows enforcement. Historical mutation populations retain
their original reports and are not folded into v07 counts.

## Troubleshooting

- Pin/inventory failure: restore the reviewed bytes; never regenerate a pin merely to pass.
- REQUESTED_POPULATION_NOT_COVERED: inspect failure.json, native.json, launch.json,
  agent stderr and raw provider JSONL. A model refusal is a failed live stage.
- Missing provider login: use its normal UI outside the lab. Never put credentials in evidence.
- LIMITED_CHILD_STARTUP_NOT_OBSERVED: hosted Windows has not established a safe
  context. Do not elevate, enable privileges or loosen ACLs.
- RECOVERY_REQUIRED: inspect journal and bytes. Do not automatically retry.

[Protocol](AGENT_TOOL_PROTOCOL_V1.md) · [boundaries](SECURITY_BOUNDARIES.md) ·
[results](../research/V07_LIVE_AGENT_RESULTS.md) · [limits](../research/V07_LIMITATIONS.md).
