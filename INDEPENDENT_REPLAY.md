# Independent replay

All commands run from repository root unless a detached worktree is stated. Outputs under `build/` are deliberately ignored runtime evidence; committed machine-readable conclusions are in `verification/security-repair-v1.json`.

## Candidate tests

```text
python -B -m unittest discover -s tests -q
python -B -m unittest discover -s tests -q
python -B -O -m unittest discover -s tests -q
```

Observed locally: 177 tests in each mode; all passed. Assertions remain enabled under `-O` because the security oracles use explicit comparisons and exceptions rather than relying on application `assert` statements.

## Gateway audit and recomputation

```text
python -B tools/audit_v0_bindings.py --out build/gateway-v1/v0-binding-audit.json
python -B -m research.gateway_abuse_replay_v0.cli evaluate --out build/gateway-v1/v0-metrics.json
python -B -m research.gateway_abuse_replay_v1.cli fixture --out build/gateway-v1/events.jsonl
python -B -m research.gateway_abuse_replay_v1.cli run --events build/gateway-v1/events.jsonl --out build/gateway-v1/report.json
python -B -m research.gateway_abuse_replay_v1.cli verify --events build/gateway-v1/events.jsonl --report build/gateway-v1/report.json
python -B -m research.gateway_abuse_replay_v1.cli evaluate --out build/gateway-v1/metrics.json
python -B -m research.gateway_abuse_replay_v1.cli mutations --out build/gateway-v1/mutations.json
python -B tools/source_mutations_v1.py --out build/source-mutations-v1/report.json
```

Observed: all four v0 binding false-ALLOW cases reproduced with empty v0 detector output; v1 second-path report comparison matched; 15/15 input/report mutants and 16/16 source mutants were killed.

## Layered integrity

Read the policy hash from the exact candidate workflow; do not derive a trusted value from an untrusted checkout.

```text
python -B tools/integrity_v1.py --policy-sha256 <PIN_FROM_EXACT_WORKFLOW> --out build/integrity-v1/report.json
python -B tools/integrity_mutations_v1.py --policy-sha256 <PIN_FROM_EXACT_WORKFLOW> --out build/integrity-v1/mutations.json
```

Observed on the final candidate inventory: baseline passed and 11/11 physical mutations were killed, with restored controls passing. Mutations cover modified/missing frozen files, legacy/PR3/repair manifest tampering, a modified/missing repair file, policy tampering, missing bootstrap, and an unexpected file.

## Historical invariant replay

The repair does not run the legacy validator against a checkout containing new research files. It checks the frozen historical tree directly:

```text
git worktree add --detach <separate-path> 03f6ffc6f4b983cfcc39f401f47165021e67e673
python -B tools/validate_v07.py --portable --out <evidence-path>
```

Observed in the detached worktree: `historical-portable exit=0`, `frozen-baseline exit=0`, overall `passed=true`, `production_ready=false`. This preserves, rather than backfills, the historical v0.7 semantics and its recorded `IMMUTABLE_V06_2_KILLED_2_CONTROL_BROKEN` history.

## Windows native assessment

```text
python -B tools/prepare.py
python -B tools/restricted_exec_v1.py --out build/windows-launch-v1.json --proof build/windows-startup-proof-v1.json --timeout 1200 tools/windows_assessment_v1.py --out build/windows-assessment-v1 --startup-proof build/windows-startup-proof-v1.json
```

The ignored embedded runtime is a test precondition, not repository evidence. `tools/prepare.py` fetched the source-pinned official runtime and verified SHA-256 `4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3` before any native PASS was accepted.

The repair preserved the failed sequence rather than replacing it with a mock. Existing PR #3 and early repair evidence reproduced `CreateProcessWithTokenW` children stalled in `LpcReply`. Direct LUA `CreateProcessAsUserW` children removed that stall but exited `0xC0000142`; positive parent and SAFER controls proved that the API and runner were functional. A SAFER NormalUser/Medium stage then started successfully and created a direct LUA restriction of its own primary token. A private desktop without the final Low/AppContainer ACL still failed the AppContainer broker controls, so that run was also retained as non-final evidence.

The final launcher uses the successful two-stage path and a disposable private window station/desktop with a Low mandatory label and access for the same user and AppContainer packages; it does not modify an existing ACL. Before `ResumeThread`, the parent independently verifies the final token has the same user, Medium integrity, administrators disabled, `elevated=false`, restrictions present, and only `SeChangeNotifyPrivilege`. The assessment verifies that the observed running token matches that pre-resume proof.

On exact implementation commit `93f0d2d68edf4cb31c3d477c766ddfd8e9f7b569`, Security repair run `43050138530` returned 41/41 v0.2 cases, 15/15 v0.4 scenarios, and `VERIFIED` for AppContainer identity, named-pipe authentication, broker permissions, nine file-access bypass attempts, execution/crash recovery, and restricted-token child startup. The assessment report SHA-256 is `a0dc2fa3a4e8dea3689fe251703a260f3052120fbd2dda98e66a70f21420ef7c`. Guardian conformance run `43050138511` independently passed its current Windows job and frozen portable replay.

## Linux local pilot

```text
python -B -m research.linux_isolated_worker_v1.pilot --image curlimages/curl:8.5.0 --out build/linux-pilot-v1/report.json
```

The named image must already be local; the pilot uses `--pull never`. Final local status was `VERIFIED_LOCAL_PILOT` with 14/14 checks true. An earlier run failed to locate cgroup v1 paths and returned `HOLD`; the probe was corrected to observe the actual Docker Desktop cgroup version and rerun. Hosted CI deliberately supplies no image and must report `NOT_COVERED` rather than pull or fake isolation.

## Fresh checkout

CI performs an actual fresh checkout with `persist-credentials: false`, recomputes normal/repeat/optimized tests, gateway evidence, source mutations, layered integrity, integrity mutations, and the exact PR #1 replay. The Windows job fetches only the URL in `runtime-lock.json`, verifies its pinned SHA-256 before native testing, uploads evidence before enforcing `status == VERIFIED`, and fails the gate for `PARTIAL`, `HOLD`, or `NOT_COVERED`. Both workflows passed at the exact implementation SHA above; production integration remains `HOLD` for the separately listed identity/provenance and Linux boundaries.
