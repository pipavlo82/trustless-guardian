# Real Hermes laboratory demo

Sequence: **ALLOW -> DENY -> BYPASS -> POLICY CHANGE -> RECOVERY -> VERIFY**.
This uses actual model inference, the native Hermes agent loop and actual
Windows AppContainer/NTFS enforcement. No model response is simulated if a
provider fails. Read the [current results](../../research/V06_REAL_AGENT_RESULTS.md)
before interpreting a run as successful.

Prerequisites: non-elevated Windows 11; Python 3.12 for the host; the pinned
installed Hermes source/venv; native Codex CLI with an existing authorized
ChatGPT login. No login export, new subscription, production key or network
capability is granted to the confined agent. Model inference uses that existing
account's quota. No automatic provider fallback or paid provider installation.

From a clean checkout of the reported research commit in PowerShell:

```powershell
python -B tools/prepare.py
python -B demo/real-agent/prepare.py --source "$env:LOCALAPPDATA/hermes/hermes-agent" --out build/guardian-lab-hermes-runtime
python -B demo/real-agent/run.py --runtime build/guardian-lab-hermes-runtime --out build/real-normal
python -B demo/real-agent/run.py --runtime build/guardian-lab-hermes-runtime --out build/real-repeat
python -B -O demo/real-agent/run.py --runtime build/guardian-lab-hermes-runtime --out build/real-optimized
python -B -m unittest discover -s tests -v
python -B -O -m unittest discover -s tests -v
python -B tools/integrity.py
```

Use a new output directory for every run. Runtime preparation requires the exact
source pin and a clean source tree. All writable data and ACL changes stay in
new `build/guardian-lab-*` directories. No real project, personal file, wallet or
browser profile is an agent target. Do not run two demos sharing one copied
runtime concurrently: each run grants that runtime's read/execute ACL to its
own disposable package SID.

The runtime manifest is itself pinned to
`fb9eab6c61bf1da7ecce053956faf29f17feb725592dd01342e1fa6d453267ac`.
Missing, changed, additional or reparse-point files are rejected before launch.
The [source lock](../../research/V06_SOURCE_LOCK.json) records all 126 installed
distribution versions; the [runtime inventory](../../evidence/v06-runtime-inventory.json)
records 14,114 exact program/dependency hashes. A differently built dependency
set requires a separately reviewed lock/profile; do not overwrite this pin to
make an incompatible installation pass.

Each scenario preserves the exact request, actual Codex JSONL, tool mapping,
Hermes frames, token/handle observation, broker response, resource snapshots and
independent verifier report. Local logs contain synthetic absolute paths; use
the public evidence exporter before publishing, and keep original hashes
distinct from redacted derivatives. Runtime binaries/dependencies stay local.

Inference is nondeterministic. The fixed tool/result predicates are compared
between runs; prompts, prose summaries, timestamps, SIDs, nonces and paths are
not claimed byte-identical. Replaying captured evidence is separate from a
fresh model-driven execution.

The model runtime is Hermes; the provider bridge is an experimental adapter to
Codex CLI, not native Nous or direct OpenAI function-call integration. The host,
provisioner, broker code and inference relay remain trusted. See
[security boundaries](../../docs/REAL_AGENT_TOOL_PROTOCOL.md).
