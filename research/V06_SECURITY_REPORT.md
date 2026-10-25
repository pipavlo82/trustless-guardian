# v0.6 real-agent security boundary

The finite local claim is that a genuine Hermes AIAgent, inside a measured
zero-capability AppContainer, can request a broker-authorized synthetic file
replacement and cannot perform the exercised direct modifications. This is not
production security, arbitrary agent support or a complete external proof chain.

The model actually selects a tool and arguments. A bounded trusted relay asks
the installed Codex CLI for inference through its existing ChatGPT login. It
translates the final schema-constrained JSON message into Hermes' tool envelope.
Hermes' unchanged registry dispatcher invokes the adapter. No expected action is
substituted if the model fails. Progress messages are retained but not executed.
The second inference summarizes the actual tool result without tools.

Three different facts are independently checked:

1. **Runtime:** separate native observer reads the actual suspended Python 3.11
   process token, image hash and handle table. It is low-integrity, non-elevated,
   AppContainer, zero capabilities, with exactly three explicitly inherited
   synthetic stdio handles. Hermes readiness reports that same PID. A
   single-process job prevents an unobserved child from escaping the observation.
2. **Authorization:** the broker independently authenticates the named-pipe
   client, verifies the exact policy/request/resource bindings, and selects the
   trusted resource path. The caller's identity field has no authority.
3. **Enforcement:** a separate process reads actual resource bytes and native
   file identities before and after each scenario. BYPASS performs real native
   write, delete, rename and extended-path write attempts from the Hermes tool
   handler, with an agent-writable scratch positive control.

The oracle imports neither Guardian's policy/broker/IPC/recovery modules nor
Hermes. It independently parses raw model transcripts, recomputes the mapping,
policy and receipt digests, and compares actual request and post-state. These
observations depend on a trusted host; they are not externally signed provider
attestations or an independent human certification.

The broker's v0.4 exception/recovery implementation remains byte-identical.
The v0.6 laboratory wrapper supplies execution-time wall clock instead of the
historical synthetic fixture clock and a bounded 110-second connection wait
for model startup. Native authentication predicates and production IPC size
limits are unchanged. The response may remain `UNVERIFIABLE / RECOVERY_REQUIRED`
with a durable `PREPARED` journal row and changed bytes. No retry is made.

## Failures retained during development

- Normal Hermes Nous credential resolution required re-login; no inference ran.
- An incomplete runtime preparation was rejected before launching an agent.
- The safe-path guard refused a runtime directory without the disposable prefix.
- Mixing the broker's Python 3.12 module path with Hermes Python 3.11 caused a
  real `_socket` import failure. Their module paths were separated.
- The historical fault worker's clock default caused a genuine EXPIRY refusal.
  A new lab-only wall-clock wrapper fixed the adapter contract.
- The one-call provider budget rejected Hermes' final summary call. The relay
  now permits exactly one action call plus one tool-free summary call.
- A missing `tools` key in that summary caused a relay failure. It was repaired.
- An oracle incorrectly expected a terminal recovery database state after the
  injected write failure. The existing documented PREPARED semantics were
  restored; the failed report was preserved rather than rewritten.
- A provider progress message and final message were initially rejected as an
  incomplete inference. Only the final schema-constrained message is now used;
  all actual messages remain in evidence. Explicit provider instructions explain
  the remote invocation rather than claiming that Codex itself owns the tools.

No demonstrated defect in the frozen Guardian core was repaired in this version.
The new work is an adapter, real-runtime evidence and conformance instrumentation.
Physical mutations measure the dependence of that full path on existing guards;
they are not newly discovered upstream vulnerabilities.

See [results](V06_REAL_AGENT_RESULTS.md), [limitations](V06_LIMITATIONS.md),
[protocol](../docs/REAL_AGENT_TOOL_PROTOCOL.md) and the machine-readable summary.
