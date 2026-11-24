# ExternalCheckpointGate — RC3 research candidate

Production HOLD. Opt-in native-boundary enforcement, not a new authorization system.
Base: 294c8a33ef29c0a08dbaa4c32a77a601b777a5b3. Historical manifests remain unchanged;
TRANSITION_PINS.json explicitly describes the three active integration edits.

## Enforcement review after b01f3eeb7ca4ee1873a0c27615adb1bf07d781a2

An explicit guardian-sql-bootstrap-ascii-v1 state profile now permits the first
laboratory dispatch: both existing SQLite tables must actually be empty; the
independently pinned request and signed grant must be present. Missing data is
never a zero observation. Dispatch arguments must match that admitted intent.
The signed chain may advance from unassigned attempt/container to the observed
native identity once; subsequent checkpoints retain that identity.

`build_protected.py DEST` builds a minimal research distribution with a fixed
module inventory. It excludes the old broker, journal executor, scoped-v1 and
other legacy launchers without editing them. Its gate has PACKAGED_REQUIRED=True:
clearing the environment does not disable direct RC3 dispatch/recovery enforcement.
`python -I -B protected_launch.py` accepts only dispatch/recover, verifies an
operator-pinned distribution manifest and requires pinned checkpoint configuration.
An existing job returns RECOVERY_REQUIRED instead of being dispatched again.
This is package isolation, not OS-wide mandatory access control. A trusted host
can still execute the full original checkout or arbitrary code outside the package.

The original entry-check removal SURVIVED under the commit-only oracle. A stronger
physical oracle observes actual Docker inspect/logs before checkpoint admission:
the same mutant is non-equivalent and KILLED; the original outcome stays archived.
A separate physical mutant disabling packaged-required mode commits without a
checkpoint and is KILLED by the SQL oracle. Initial CONTROL_BROKEN from unsupported
isolated raw-script imports is retained, not counted as a kill.

One initial and one final deliberately distinct synthetic session each executed
one worker. Each continued EMPTY -> RESULT_OBSERVED -> COMMITTED across physical
crashes, with no repeated worker start. The final runtime includes packaged-mode
hardening. Native authorization used a trusted-host synthetic principal and signed
grant; a fresh AppContainer broker handshake is not claimed by these tests.
Checkpoint source_sha retains the explicit b01 source-base pin. Exact candidate
runtime is independently pinned by the distribution manifest; do not reinterpret
that historical field as the later commit SHA or as a signed runtime-build digest.

Final local evidence: 223 unit tests per normal/repeat/-O, 118 separate offline
oracle checks per mode, 12 protected entry checks, 28 excluded paths probed in
two interpreter modes. A freshly signed stale head is accepted as laboratory
CURRENT if the high-water pin is also old; a retained newer pin rejects it.
Strict mode still holds. REMOTE_FINALITY/TRUSTED_LATEST_HEAD and host-wide
mandatory enforcement remain NOT_ESTABLISHED; production HOLD.

## Authority and entrypoints

`lab.execute` checks the checkpoint before any admission or Docker creation and
rechecks the admitted snapshot against a fresh signed remote challenge immediately
before Docker start. Existing authenticated request, policy, grant, principal,
expiry and replay checks still run. CURRENT is never a grant.

`reconcile_v3_hardened.reconcile` is decorated at entry and rechecks before its
SQLite commit. `guardian_rc2_server.py --recover ROOT` invokes this same entrypoint.
The original fresh-session supervisor path still uses `lab.execute`.
The new supervisor recovery CLI does not launch a Docker worker.

Set GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED=1 in the trusted supervisor environment,
GUARDIAN_CHECKPOINT_CONFIG to an operator-owned JSON path, and
GUARDIAN_CHECKPOINT_CONFIG_SHA256 to its independently pinned exact bytes.
Missing/invalid required configuration fails closed. Absence of the REQUIRED
variable retains historical opt-out behavior in the full research checkout only.
The minimal distribution fixes required mode at build time. Trusted host Python introspection,
legacy `guardian/broker.py`, `guardian/hardened.py`, `guardian/dispatch.py` and older
research executors are outside this coverage. Repository-wide non-bypass enforcement
is NOT_ESTABLISHED; do not expose those executors as alternate agent interfaces.

## Trust and state

Config schema is guardian.external-checkpoint-config.v1; fields are schema,
state_root, lock_path, provider, trust_policy, trust_policy_sha256, chain_path.
The lock must live outside the rolled state directory in trusted supervisor storage.
Config/trust roots are selected by the supervisor, not by uploaded evidence.
The separate verifier rechecks Ed25519, native request/grant/receipt bindings,
logical SQLite admission/transitions and evidence byte hashes. Checkpoint domain:
UTF-8 `guardian.checkpoint.v1` followed by NUL and canonical record bytes.
Envelope head is SHA-256 of the same domain plus canonical envelope bytes.
The profile restricts canonical JSON to ASCII and safe integers; SQL integer
values are decimal strings. Physical WAL hashes alone are not authenticated
logical state. Snapshot correctness requires owned quiescent history and no
uncoordinated writer. Operation serialization protects cooperating gate callers;
it does not defend against malicious host administrators.

Only provider=synthetic_challenge with GUARDIAN_CHECKPOINT_LAB_ONLY=1 can admit
laboratory CURRENT. This is explicitly same-host/same-admin trust. Every other
provider currently returns FINALIZED_PROVIDER_NOT_IMPLEMENTED/HOLD.
Independent finality, latest-head discovery and administrator independence remain
NOT_ESTABLISHED. The browser module is read-only and never returns a permission token.

## Crash consistency

State1 is RESULT_OBSERVED with an already published native receipt. Under a current
laboratory checkpoint1, recovery can commit the original verified result. A crash
before SQLite commit leaves state1. A crash after commit but before checkpoint2
publication leaves state2 versus checkpoint1 and fails closed. No automatic
publication, reconciliation retry or worker repeat occurs. Locks are released by
process exit/OS death. Operator-authorized checkpoint publication/finalization is
required to leave this HOLD; publishing a checkpoint is not implemented here.
The explicit bootstrap profile covers a first protected dispatch. Multiple-admission
progression is not covered by the current single-lineage profile. A dispatch with
a physical crash and successful reconciliation is tested; this is not a fresh
AppContainer authentication test or arbitrary external API exactly-once guarantee.

## Verification

Run `python -B -m unittest discover -s tests -v`, repeat, and repeat with `-O`.
The independent evidence package supplies offline_audit.py, native physical crash
logs, SQLite/WAL snapshots, Engine readbacks, 19 scenario outcomes and mutations.
The mutation removing both checks is KILLED by an actual forbidden SQL commit;
removing only the entry check SURVIVED because the commit check rejected the missing
lease. This is not proof of global equivalence. No exception/crash is counted KILLED.

Web candidate tests exercise signatures and selected state pins only, not SQLite
recomputation or external anchor verification. No existing website files are changed.
