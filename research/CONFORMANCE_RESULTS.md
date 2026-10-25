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
