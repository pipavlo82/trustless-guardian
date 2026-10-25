# v02 measured results

Starting commit: `7c43ff437d15cc29bc61f85683ed0fb091dff0be`. Main remains `aaa941cf3566a6931cba539e4d8147d940459171`.
Full fresh-checkout code replay: `d6ee623eecaeffe6aaf079986af84afc2a2d3660`.
Later handle-witness addition is tested separately and changes no broker/IPC/
recovery/policy implementation. Final source identities are checked against the
published tree; raw commands and per-file hashes are in the v02 evidence archive.

| Executed group | Normal | Repeat | Python -O |
| --- | --- | --- | --- |
| Current unit suite (14 unchanged v0 + 6 new) | 20 | 20 | 20 |
| Existing v0 policy/resource scenarios | 17/17 | 17/17 | 17/17 |
| v02 adversarial cases | 41/41 | 41/41 | 41/41 |
| Inheritable host-handle refusal | PASS | PASS | PASS |
| Semantic output comparison | identical | identical | identical |

Semantic SHA-256: `bf942e4341ceac799d382be75dfa0cb463da27cf79aae4ebc102899b74cea6f0`.
The v02 matrix includes nine independently observed agent direct denials, five
broker scope denials, four locked TOCTOU operations, actual file symlink and
hardlink controls, authenticated/unauthorized clients, envelope substitution,
concurrent nonce reuse, restart replay, unknown/missing journal and four crash
stages. Every direct operation gets a host byte snapshot. These are finite
observations, not universal OS confinement or production claims.

Historical baseline was replayed before edits: 14 unit tests/mode, 17 scenarios,
15 physical mutants killed, all four evidence archives and 47 inventory entries
valid. The current regression run additionally discovers the six new unit tests;
it does not turn them into historical v0 results.

New physical population: 11 KILLED / 0 SURVIVED /
0 CRASHED / 0 NOT_APPLIED /
0 CONTROL_BROKEN. The same population was replayed under
`-O`; do not double-count it. Existing v0 15/15 remains a separate population.

The native ReceiptOS probe is unavailable because its read-only checkout lacks
`@noble/curves`. VECA evaluate/admit executes and refuses; the native proof binary
and prepared crypto dependency tree are absent, so no complete native verification
is claimed. Native statuses are preserved. All evidence-to-action integration is
NOT_COVERED. No six-field RVR receipt or upstream repository was changed.

Hosted CI must be read from the exact published commit. Local replay is independent
of the broker process and uses a separate oracle implementation, but is not an
independent human/organization review. Recommendation: **ITERATE**.

## Historical v0 report (preserved)

# Guardian v0 conformance results

Initial foundation commit: `aaa941cf3566a6931cba539e4d8147d940459171`.
Development branch: `research/guardian-enforcement-v0`.
Machine-readable reports and raw evidence are indexed in [evidence](../evidence/README.md).

## Local execution

Observed on Windows, NTFS D: storage, host and embedded Python 3.12.10 x64.
The host token was non-elevated. The child was separately launched with a real
AppContainer SID, low integrity and zero capabilities. No local account, password,
administrator elevation, production credential or network service was used.

| Test group | Normal | Repeat | Python -O |
| --- | --- | --- | --- |
| Guardian unit tests | 14 passed | 14 passed | 14 passed |
| Policy/resource scenarios | 17/17 expected outcomes | 17/17 | 17/17 |
| Direct OS access + scratch positive | 9 rejected / scratch succeeds | Same | Same |
| Gateway unavailable / broker unavailable | Protected bytes unchanged in both | Same | Same |
| Tampered evidence | Independent verifier exit 1 | Same | Same |
| Semantic output comparison | Reference | Byte-identical | Byte-identical |

The 17 outcomes contain 1 VERIFIED + ALLOW, 15 REFUTED + DENY, and 1
UNVERIFIABLE + DENY. Each is checked by a separate verifier process and a host
read of the actual file. The ALLOW case yields exact `approved:allow` bytes.

| Scenario | Expected and observed boundary |
| --- | --- |
| allow | Exact approved bytes written |
| deny_action | Non-replacement action refused |
| wrong_actor / wrong_resource | Identity/resource binding refused |
| expired / future_expiry | Expired or excessively long validity refused |
| wrong_version | Policy-version substitution refused |
| missing_evidence | UNVERIFIABLE + DENY |
| wrong_precondition | Mismatched prior bytes refused |
| wrong_scope | Broader scope refused |
| unconsumed_field | Extra `authorized` field refused |
| wrong_path | Filesystem pathname cannot replace symbolic resource |
| bad_content | Content outside finite policy refused |
| forged_gateway_allow | Broker recomputation overrides forged client permission |
| replay | Already consumed nonce refused |
| policy_change | Changed policy between gateway and broker refused |
| resource_replacement | Same bytes at a replacement file identity refused |

The direct-access witness executes write, delete, rename, extended-path write,
junction write, policy write, parent-directory rename, hard-link creation and
native CreateFile write-open. All nine received OS access rejection; the child
completed successfully and could write its allowed scratch file. Protected bytes
were unchanged. No successful hard-link creation occurred, so hard-link-write
coverage is not claimed.

Component-unavailable cases deliberately omit gateway/broker dispatch and run
the actual direct attacks. They establish continued confinement for these paths,
not service availability. Evidence verification alone remains insufficient to
prove physical prevention.

## Evidence interpretation

Normal/repeat/optimized raw logs differ in process IDs, package SIDs, paths and
timing. The semantic projection retains case identities, decision/reason,
broker result, host byte digests, verifier exit codes and OS error outcomes.
Those semantic bytes are compared exactly; raw cross-platform identity is not claimed.

The independent verifier is separately implemented Python code in a separate
process. Fresh-checkout replay is independent of the working directory, not an
independent human review, operating system implementation or trusted host.

The four original prototype tests were independently rerun and its three source
files remained byte-identical. Those tests establish policy behavior only; they
are not counted as new OS-enforcement tests.

## Development observations preserved

Before the successful boundary witness, one process launch failed with WinError
203 due to an insufficient environment block. A second child exited 0xC0000022
before producing a witness because existing extracted runtime files did not
have explicit AppContainer ACL entries. Both were infrastructure failures, never
enforcement passes. The environment was allowlisted and each newly extracted
runtime file received its intended ACL. Original machine-readable probe failure
files were not retained; this paragraph is a development account, not a fabricated
raw transcript. Later successful lab/mutation stdout and stderr are preserved.

## Recommendation

**ITERATE.** The local OS boundary is demonstrated with a load-bearing ACL
counterfactual. Production broker privilege separation, authenticated service
transport, durable crash recovery, native integrations and independent review
remain open. External execution is UNVERIFIABLE; no full external chain or
production security claim follows from these finite tests.

## Fresh-checkout corroboration

A separate `git clone --no-local` reproduced the implementation at
`977f9b33873fa0506b5599e73897b24f9eb7c23f`, including all 15 mutations under
Python `-O`. After adding the DACL ownership control, a clean detached checkout of
`d5812be5a8dbd7b8ac9c0e579fae517905486291` reran the full validator: 14 tests
per mode, 17 scenarios per mode, the direct OS controls, the ownership control,
15 normal-mode mutations, archive verification and repository inventory all passed.

`tools/ownership_control.py` separately attempts `SetFileSecurityW` from the real
AppContainer to grant write access through the file's DACL. The child exits zero,
writes its scratch positive control, receives WinError 5 for DACL modification,
and leaves protected bytes unchanged. This addresses the shared TokenUser SID
question for that concrete API; it is not a proof of all ownership-related APIs.

All recorded Python source hashes were checked against the cited Git commits
after execution, with zero mismatches. The fresh worktree was clean. The exact
semantic-output SHA-256 is identical across original/fresh/normal/repeat/optimized:
`d723638ac4ded84070d5d832c85fbfdd153f28bdafa965cf0142254cf6f5aac5`.

The two mutation runs exercise the same 15 physical variants; they are not
reported as 30 distinct mutants. Raw records are in `evidence/fresh-replay-v0.zip`.
The publication commit `3c2ae0d` changed only evidence/documentation after that
replay. Subsequent CI-entry and diagnostic changes, and the first failed hosted
Windows runs, are described separately in [CI portability](CI_PORTABILITY.md).
Hosted results must always be attributed to their exact HEAD.

The final implementation at public commit `1a8aa03bea916f62e26eb92b41374a10cf4c556b`
was cloned again from GitHub. Normal/repeat/optimized unit and OS runs, the DACL
ownership control, all 15 optimized physical mutations, every archive hash and
repository inventory passed. The fresh clone was clean and every recorded source
hash matched its Git blob; semantic SHA-256 remained `d723638a...f6f5aac5` as above.
This local result coexists with hosted Windows CI_BLOCKED (WinError 1312), not
hosted OS verification. Both observations are preserved in `public-replay-v0.zip`.
