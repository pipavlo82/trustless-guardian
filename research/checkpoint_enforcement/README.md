# ExternalCheckpointGate — RC3 research candidate

Production HOLD. Opt-in native-boundary enforcement, not a new authorization system.
Base: 294c8a33ef29c0a08dbaa4c32a77a601b777a5b3. Historical manifests remain unchanged;
TRANSITION_PINS.json explicitly describes the three active integration edits.

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
variable retains historical opt-out behavior. Trusted host Python introspection,
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
Fresh empty-history bootstrap and multiple-admission progression are not covered
by the current single-lineage profile. A fresh successful protected dispatch under
the enabled gate is NOT_TESTED; denial and existing-worker reconciliation are tested.

## Verification

Run `python -B -m unittest discover -s tests -v`, repeat, and repeat with `-O`.
The independent evidence package supplies offline_audit.py, native physical crash
logs, SQLite/WAL snapshots, Engine readbacks, 19 scenario outcomes and mutations.
The mutation removing both checks is KILLED by an actual forbidden SQL commit;
removing only the entry check SURVIVED because the commit check rejected the missing
lease. This is not proof of global equivalence. No exception/crash is counted KILLED.

Web candidate tests exercise signatures and selected state pins only, not SQLite
recomputation or external anchor verification. No existing website files are changed.
