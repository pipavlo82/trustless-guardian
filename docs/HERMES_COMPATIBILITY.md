# Hermes compatibility audit v0.7

**Pinned experimental integration, not general Hermes support.**
Hermes 0.20.6 at f7c79efbac19ae18e8dee7c79a4e4c0935299b5f, Python 3.11.16,
OpenAI SDK 2.24.0; 14,114 runtime files pinned by manifest SHA-256
fb9eab6c61bf1da7ecce053956faf29f17feb725592dd01342e1fa6d453267ac.
Hermes is MIT; existing notices remain. Installed source/config/credentials are unchanged.

Official [plugin docs](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins)
expose register(ctx)/ctx.register_tool. The
[tool runtime docs](https://hermes-agent.nousresearch.com/docs/developer-guide/tools-runtime)
describe registry registration. Pinned hermes_cli/plugins.py and tools/registry.py
were inspected; see [file hashes](../research/V07_SOURCE_AUDIT.json).

The adapter registers two laboratory tools and executes actual AIAgent.run_conversation.
Its inference transport installs httpx through `_client_kwargs`, `_disable_streaming`
and `_replace_primary_openai_client`. These private attributes are not a public
compatibility contract. Public plugin registration does not itself provide this
credential-free inherited-stdio provider transport under the zero-capability,
one-process policy. A documented drop-in mechanism for that restriction was not
established. The pinned transport remains experimental; general plugin/MCP
deployment and native Nous/OpenAI provider operation are NOT_COVERED.

Trusted host Codex CLI supplies genuine gpt-6-luna inference. Actual model JSON is
explicitly converted into a Hermes tool envelope. IDs/created/zero usage in that
envelope are local placeholders; original JSONL, invocation metadata, request
digest and tool binding are separate evidence. No provider-signed call or remote
attestation is claimed. The host relay is not AppContainer-confined.

The copied runtime requires the exact installed dependency file set. Independent
dependency bootstrap and cross-host compatibility are not established. Earlier
Cursor/Grok/native Nous limitations remain historical facts.
