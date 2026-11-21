<div align="center">

# 🛡️ Trustless Guardian

### AI agents can propose actions. They should not grant themselves permission to execute them.

**Authenticate → Authorize → Isolate → Record → Recompute**

[![Research](https://img.shields.io/badge/STATUS-ACTIVE_RESEARCH-7950F2?style=for-the-badge)](https://github.com/pipavlo82/trustless-guardian/pulls)
[![Production](https://img.shields.io/badge/PRODUCTION-HOLD-E8590C?style=for-the-badge)](https://github.com/pipavlo82/trustless-guardian/pull/8)
[![Draft PR8](https://img.shields.io/badge/LATEST-DRAFT_PR_%238-228BE6?style=for-the-badge)](https://github.com/pipavlo82/trustless-guardian/pull/8)
[![License](https://img.shields.io/badge/LICENSE-Apache--2.0-12B886?style=for-the-badge)](LICENSE)

**Gates, not scores.** · **Don't trust. Recompute.**

[Architecture](#-how-guardian-works) · [Resonance Core](#-what-is-resonance-core) · [Roadmap](#-research-roadmap) · [Draft PR #8](https://github.com/pipavlo82/trustless-guardian/pull/8)

</div>

---

## ⚡ Why Guardian exists

An AI agent can request a tool call, receive a policy response, and claim that an action happened. Those are **different claims**.

Trustless Guardian investigates a stricter boundary: an agent proposes an action; separately controlled policy and operating-system mechanisms enforce permissions; independent evidence checks establish what can actually be proven.

> **Verification ≠ Authorization ≠ Enforcement ≠ Evidence of Execution.** A valid signature is not evidence that an external action occurred. A policy decision alone is not an OS block. Green CI is not production security approval.

### 🧩 Research components

| Layer | What it does | Where to review |
| :--- | :--- | :--- |
| 🔑 **Identity** | JWT / EIP-4361 SIWE / scoped MCP bearer authentication | [Draft #5](https://github.com/pipavlo82/trustless-guardian/pull/5) |
| 🛂 **Authorization** | Binds request, tool, resource, time and signed grants | [Drafts #5–6](https://github.com/pipavlo82/trustless-guardian/pull/6) |
| 🧱 **Containment** | Windows AppContainer and constrained Linux research pilots | [Drafts #4–7](https://github.com/pipavlo82/trustless-guardian/pull/7) |
| 🧾 **Evidence** | Preserves lifecycle decisions, observations and receipt evidence | [Draft #6](https://github.com/pipavlo82/trustless-guardian/pull/6) |
| 🔍 **Recompute** | Independent verification paths and mutation-based negative controls | [Drafts #6–8](https://github.com/pipavlo82/trustless-guardian/pull/8) |
| 🧠 **Resonance Core** | Deterministic state changes and proposal-only decision research | [Draft #7](https://github.com/pipavlo82/trustless-guardian/pull/7) |

**These components live across separate, stacked Draft PRs. They are not a production-integrated platform.**

## 🗺️ How Guardian works

Conceptual security architecture, drawing on **bounded research paths**, not an end-to-end production claim:

~~~mermaid
flowchart TD
    A["🤖 Agent proposes an action"] --> B["🔑 Identity and request binding"]
    B --> C{"🛂 Policy permits it?"}
    C -->|"No / unknown"| H["🛑 DENY or HOLD"]
    C -->|"Scoped admission in research pilots"| E["🧱 Constrained execution boundary"]
    E --> F["🧾 Observations and receipt evidence"]
    F --> G["🔍 Independent verifier"]
    H --> G
    G --> I{"Evidence sufficient?"}
    I -->|"Under stated assumptions"| J["Bounded verified claim"]
    I -->|"Missing / contradictory"| K["NOT_ESTABLISHED or REFUTED"]
    classDef stopped fill:#fff4e6,stroke:#e8590c,color:#8f2500;
    classDef checked fill:#e7f5ff,stroke:#1c7ed6,color:#0b4d80;
    class H,K stopped;
    class G,I,J checked;
~~~

The current Resonance/Guardian IPC experiment is **HOLD-only**. It does **not** issue execution grants or launch workers.

## 🧠 What is Resonance Core?

**Resonance Core is an experimental deterministic state-and-decision engine — not a chatbot and not a new LLM.**

The original Python core tracks a small evolving internal state, accepts seven normalized observations, measures change and load, and returns one of four bounded decisions. The original file is preserved **byte-for-byte** in [Draft PR #7](https://github.com/pipavlo82/trustless-guardian/pull/7).

| Signal / state | What it means |
| :--- | :--- |
| <code>cpu</code>, <code>memory</code>, <code>disk</code> | Normalized load-related signals |
| <code>hour_sin</code>, <code>hour_cos</code> | Mathematical time-of-day features |
| <code>solar_proxy</code>, <code>lunar_proxy</code> | **Illustrative time-phase proxies**, not real astronomy or sensor readings |
| <code>attention</code>, <code>energy</code>, <code>phase</code> | Numeric state; **not** consciousness, emotions or biological fatigue |
| <code>novelty</code>, <code>pressure</code> | Computed change and load indicators |

Its four possible outputs are **<code>OBSERVE</code>**, **<code>INVESTIGATE_CHANGE</code>**, **<code>REVIEW</code>** and **<code>DEFER</code>**.

### 🔒 Resonance inside the Guardian experiment

~~~mermaid
flowchart LR
    S["Synthetic observations"] --> R["🧠 Original Resonance State/decide"]
    R --> P["Bound proposal-only IPC request"]
    P --> B["🛡️ Guardian broker: SID and signed replies"]
    B --> H["HOLD_GUARDIAN_GRANT_REQUIRED"]
    classDef hold fill:#fff4e6,stroke:#f08c00,color:#8c4200;
    class H hold;
~~~

The confined Windows AppContainer pilot **disables real sensor imports** and runs three steps of the original core over synthetic signals. [Draft PR #8](https://github.com/pipavlo82/trustless-guardian/pull/8) adds pinned Ed25519 broker-reply authentication, bounded cancellable pipe I/O and offline evidence verification around this path.

It does **not** contain live LLM inference, continuous autonomous operation, conversational memory, tool execution, or verified human-intent detection. The original core has a SHA-256-chained log format in its standalone mode; that alone does not prove real-world action or authenticated process origin.

**Learn more:** [Resonance Core explained](docs/RESONANCE_CORE.md) · [Pinned source](https://github.com/pipavlo82/trustless-guardian/blob/2a40075a7f217e9c385cdfaf27c0267fa788d574/research/resonance_guardian_v1/reference_core/agent.py) · [Windows pilot README](https://github.com/pipavlo82/trustless-guardian/blob/2a40075a7f217e9c385cdfaf27c0267fa788d574/research/resonance_guardian_v1/README.md)

## 🚀 Research roadmap

**Repository topology:** <code>main</code> holds the original foundation. These **eight open Draft PRs** are stacked on one another and **have not been merged into main**.

| Draft | Milestone | Research focus |
| :---: | :--- | :--- |
| [#1](https://github.com/pipavlo82/trustless-guardian/pull/1) | Agent preview | Experimental Hermes/Codex tool boundary and OS controls |
| [#2](https://github.com/pipavlo82/trustless-guardian/pull/2) | Rare-event evidence | Synthetic anomaly triage, never an authorization grant |
| [#3](https://github.com/pipavlo82/trustless-guardian/pull/3) | Gateway abuse replay | Synthetic policy simulation and recomputed findings |
| [#4](https://github.com/pipavlo82/trustless-guardian/pull/4) | Security repair | Windows enforcement, integrity checks and negative tests |
| [#5](https://github.com/pipavlo82/trustless-guardian/pull/5) | Authentication | JWT / SIWE / MCP scopes, grants and Linux isolation pilot |
| [#6](https://github.com/pipavlo82/trustless-guardian/pull/6) | Durable replay | One-use challenges, lifecycle states and receipt evidence |
| [#7](https://github.com/pipavlo82/trustless-guardian/pull/7) | Resonance + IPC | Original core in an AppContainer; proposal-only HOLD |
| **[#8](https://github.com/pipavlo82/trustless-guardian/pull/8)** | **Mutual IPC** | **Signed broker replies, bounded I/O, parity checks, integrity v8** |

Reviewing a later PR **does not approve earlier stages**.

## 🧪 Evidence, not marketing

<div align="center">

[![PR8 CI](https://img.shields.io/badge/PR_%238_CI-4%2F4_WORKFLOWS_GREEN-2F9E44?style=flat-square)](https://github.com/pipavlo82/trustless-guardian/pull/8/checks)
![Offline fix](https://img.shields.io/badge/OFFLINE_FIX-BOUNDED_VALIDATION-228BE6?style=flat-square)
![Human review](https://img.shields.io/badge/SECURITY_REVIEW-PENDING-F59F00?style=flat-square)

</div>

At [Draft PR #8 head <code>299487d</code>](https://github.com/pipavlo82/trustless-guardian/commit/299487d7d7884b2cb2adc7df86b6485ee18daba7), **four GitHub Actions workflows completed successfully on 15 November 2026**. The separately recorded local evidence includes:

- **48/48** mutual-IPC unit tests per normal, repeat and optimized run.
- **28/28** native Windows AppContainer scenarios at frozen IPC source <code>be31c67</code>; **28/28** historical offline evidence classifications recomputed. **Not remote OS attestation.**
- **7/7** offline evidence source mutants killed with discriminating witnesses; **7/7** v8 integrity negative controls killed in disposable copies.
- **386 protected paths** under integrity v8, with historical policies preserved.

A historical, operator-selected review policy is **not current production trust-root authorization**. CI success is not universal isolation proof, independent human approval or complete grant → worker → terminal receipt integration.

## 🔎 Explore the project

| Resource | What you will find |
| :--- | :--- |
| [Architecture](docs/ARCHITECTURE.md) | Foundation: policy, broker, OS boundary and evidence |
| [Security scope](docs/SECURITY_BOUNDARIES.md) | Threat model, assumptions and exclusions |
| [Resonance Core guide](docs/RESONANCE_CORE.md) | Inputs, deterministic decisions and IPC research boundary |
| [Draft PR #8](https://github.com/pipavlo82/trustless-guardian/pull/8) | Latest source, evidence classification and reproduction steps |
| [Draft PR #7](https://github.com/pipavlo82/trustless-guardian/pull/7) | Original Resonance Core and AppContainer experiment |

To **inspect** the latest Draft branch instead of the foundation:

~~~bash
git clone https://github.com/pipavlo82/trustless-guardian.git
cd trustless-guardian
git fetch origin pull/8/head:guardian-pr8-review
git switch guardian-pr8-review
# Follow the pinned dependencies and review instructions in PR #8.
~~~

**Use disposable laboratory inputs only. Do not run these experiments against production keys, wallets, customer records or external services.**

## 🧱 Explicit non-claims

- ❌ Not a production-ready security appliance or an AI capable of reading human intentions.
- ❌ Not blanket permission for agents to use arbitrary tools.
- ❌ Not proof of actual execution merely because a receipt is signed.
- ❌ Not established production key custody, root distribution, revocation or anti-rollback.
- ❌ Not a fully integrated execution-grant → isolated-worker → terminal-receipt pipeline.
- ❌ Not a universal Windows/Linux confinement guarantee beyond the tested laboratory scope.

**Release decision: RESEARCH / DRAFT · independent human security review required · PRODUCTION HOLD.**

## 🤝 Principles and license

- **Gates, not scores.** Keep authorization, enforcement, observation and recomputation separate.
- **Don't trust. Recompute.** Build independently checkable evidence, not self-reported PASS.
- **A failed test is a result.** Never reclassify <code>SURVIVED</code>, <code>CRASHED</code>, <code>NOT_COVERED</code> or <code>NOT_ESTABLISHED</code> as verified.
- **Preserve provenance.** Pin source, retain failed controls and version integrity transitions.

Original code is licensed under [Apache-2.0](LICENSE). Third-party components retain their own licenses. Open source is **not** security certification.

<div align="center">

**Verifiable AI-agent security research. No trust-by-marketing.**

[Browse Draft PRs](https://github.com/pipavlo82/trustless-guardian/pulls) · [Security boundaries](docs/SECURITY_BOUNDARIES.md)

</div>

## Historical PR #1 replay boundary

The original [PR #1 README at its reviewed commit](https://github.com/pipavlo82/trustless-guardian/blob/03f6ffc6f4b983cfcc39f401f47165021e67e673/README.md) remains the versioned entry point for the v0 through v0.7 laboratory results, commands, failures and limitations.

This documentation reconciliation preserves the current project overview and the original research history. It does not reclassify historical CI failures or mutation survivors. PR #1 through #8 remain separate review units; later passing checks do not validate earlier heads or a new integration composition. The scoped execution candidate requires third-party replay before any integration decision. Production remains **HOLD**.
