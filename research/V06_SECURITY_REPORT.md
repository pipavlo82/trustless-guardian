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

An additional adapter preflight defect was found during review: checking only
listed file hashes allowed an unlisted runtime module to escape the inventory
check. The final preflight pins the manifest itself, requires an exact file set,
rejects reparse paths, and checks every file hash. Negative controls cover an
extra module, missing module, changed module and caller-resealed manifest. No
unexpected module was observed in the actual recorded runtime. This is a
pre-launch integrity repair, not evidence of a prior OS confinement bypass.

No demonstrated defect in the frozen Guardian core was repaired in this version.
The new work is an adapter, real-runtime evidence and conformance instrumentation.
Physical mutations measure the dependence of that full path on existing guards;
they are not newly discovered upstream vulnerabilities.

The final mutation classifier also requires the specific unsafe behavior in raw
resource observations, beyond a failed verification predicate. A false predicate
without changed bytes/unsafe outcome is `CONTROL_BROKEN`, not `KILLED`. This
closes a measurement weakness in the development classifier. The original
development report is preserved; its four reported kills also have the required
byte-level witnesses. A new campaign independently executes the stricter logic.

See [results](V06_REAL_AGENT_RESULTS.md), [limitations](V06_LIMITATIONS.md),
[protocol](../docs/REAL_AGENT_TOOL_PROTOCOL.md) and the machine-readable summary.

## Independent review checklist

- Pin the reported checkout and verify the complete repository and archive
  inventories before execution. Confirm `guardian/` matches the starting SHA.
- Distinguish an offline replay of captured observations from a fresh live model
  run. Preserve provider failures; do not substitute a scripted client.
- Inspect actual raw model output, its explicit conversion and the Hermes tool
  observation. A readiness message or version banner is insufficient.
- Inspect the separately captured native process token, exact package SID,
  image hash and selected handle table. Confirm the agent, not only its launcher,
  has the measured confinement attributes.
- Recompute the trusted policy and receipt preimages, and verify the authenticated
  pipe identity against the separately observed process identity.
- Read protected resource bytes independently after every denial/bypass. Check
  the scratch positive control and the successful broker ALLOW path.
- Confirm changed bytes plus a PREPARED journal remain an ambiguous execution
  outcome. No automatic retry or exactly-once claim is permitted.
- Re-run each physical mutation with baseline and restored controls. Require
  the specific unsafe behavior; do not count crashes or unavailable evidence.
- Keep same-host evidence, a second-machine replay, hosted CI, independent human
  review and production authorization as separate claims.
