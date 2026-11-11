# Gateway abuse replay v1 — bounded synthetic repair

Status: **RESEARCH / HOLD**. This additive version repairs authorization-oracle and detector defects found in v0 without rewriting v0 evidence. It performs no network calls, tool execution, JWT verification, wallet lookup, deployment, or production enforcement.

The v1 policy binds the authenticated synthetic subject, token subject, presented wallet, token wallet, role, agent owner, service identity, destination, and payload. Public health accepts one exact no-side-effect shape. Anomaly detection remains a separate triage path and is never an authorization input.

The held-out corpus is separate from the functional trace and includes legitimate administrative, owner, runner, MCP, and Telegram activity. Its labels are not available to either detector. Metrics are deterministic synthetic measurements, not statistical or real-world claims.

Run from the repository root:

```text
python -B -m unittest discover -s tests -p test_gateway_abuse_replay_v1.py -v
python -B -O -m unittest discover -s tests -p test_gateway_abuse_replay_v1.py -q
python -B -m research.gateway_abuse_replay_v1.cli fixture --out build/gateway-v1/events.jsonl
python -B -m research.gateway_abuse_replay_v1.cli run --events build/gateway-v1/events.jsonl --out build/gateway-v1/report.json
python -B -m research.gateway_abuse_replay_v1.cli verify --events build/gateway-v1/events.jsonl --report build/gateway-v1/report.json
python -B -m research.gateway_abuse_replay_v1.cli evaluate --out build/gateway-v1/holdout.json
python -B -m research.gateway_abuse_replay_v1.cli mutations --out build/gateway-v1/mutations.json
```

`ALLOW` and `DENY` are counterfactual policy-simulation values only. JWT signature/issuer/audience verification, wallet ownership, registry state, event provenance, and real enforcement remain `NOT_COVERED`.

