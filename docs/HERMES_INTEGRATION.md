# Hermes integration v0.6

The installed runtime selected for this experiment is Hermes Agent 0.20.6,
local source `f7c79efbac19ae18e8dee7c79a4e4c0935299b5f` (upstream version banner
`3eb7ed08`, one carried commit), Python 3.11.16, OpenAI Python SDK 2.24.0.
The source tree was clean. Its MIT license is preserved; no upstream source is
modified or vendored into this repository.

The normal configured Nous provider (`upstage/solar-pro4:free`) failed credential
resolution with `AuthError`, `relogin_required=true`, before inference. No key,
auth file, private conversation or credential was copied to the laboratory.

Codex CLI 0.162.0-alpha.17.2 completed a genuine minimal inference using the
existing ChatGPT login. Its executable SHA-256 is
`e98c516f1c8935789aabe9122ee7e05ec4c3efd1ba6acf179242e031c495b99e`.
The experimental relay uses `gpt-6-luna`, low reasoning, ephemeral execution,
read-only sandbox, no user config/rules, disabled shell and web search, and a
strict JSON output schema. Model-selected JSON is converted to a Hermes
ChatCompletion tool-call envelope; raw provider responses and the conversion
are preserved separately.

Cursor 3.18.9 (`2ba48ff3f7514cc4643c52ca9f7b3173d9b66130`) exposed the desktop
CLI. `agent --help` returned the ordinary desktop help; no usable standalone
agent transport was established. Grok Bot 0.71.2 was identified from its local
ASAR package metadata; no isolated CLI/provider path was established. Their
inference, tools and confinement remain **NOT_COVERED**.

The synthetic Hermes home disables tool-search indirection and exposes only the
two Guardian laboratory tools. Context files, memories, background review and
fallback providers are disabled. The native AIAgent conversation and registry
dispatch execute inside the observed AppContainer; this is not a scripted
Python replacement described as an agent.

This integration uses the pinned Python AIAgent API and its private client
replacement hook. It is not an installed Hermes CLI plugin or a stable upstream
transport contract. A Hermes upgrade requires renewed source review and replay;
the current source/runtime pins intentionally reject an unreviewed replacement.

Runtime preparation copies only program/dependency files into a new disposable
directory. Installed profiles, `.env`, auth stores and user memory are excluded.
The copied Python 3.11 runtime and broker Python 3.12 runtime have separate module
paths. No installed runtime ACL or system security setting is changed.

See [protocol](REAL_AGENT_TOOL_PROTOCOL.md), [demo](../demo/real-agent/README.md),
[actual results](../research/V06_REAL_AGENT_RESULTS.md), and
[limitations](../research/V06_LIMITATIONS.md).

Primary runtime references: [Hermes providers](https://hermes-agent.nousresearch.com/docs/integrations/providers),
[Codex authentication](https://learn.chatgpt.com/docs/auth),
[Codex non-interactive execution](https://learn.chatgpt.com/docs/non-interactive-mode).
Local executable behavior and pinned source, rather than these evolving pages,
determine the executed experiment.
