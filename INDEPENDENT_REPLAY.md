# Independent replay

All commands run from repository root unless a detached worktree is stated. Outputs under `build/` are deliberately ignored runtime evidence; committed machine-readable conclusions are in `verification/security-repair-v1.json`.

## Candidate tests

```text
python -B -m unittest discover -s tests -q
python -B -m unittest discover -s tests -q
python -B -O -m unittest discover -s tests -q
```

Observed locally: 176 tests in each mode; all passed. Assertions remain enabled under `-O` because the security oracles use explicit comparisons and exceptions rather than relying on application `assert` statements.

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
python -B tools/windows_assessment_v1.py --out build/windows-assessment-v1
```

Observed on Windows 11: v0.2 exited 0 in 62.757 seconds, v0.4 exited 0 in 96.548 seconds, diagnostics exited 0, 41 cases and 15 recovery scenarios were present. Overall status was `PARTIAL` because restricted-token startup was `NOT_COVERED` for the non-elevated caller.

Existing upstream PR #3 Windows Server 2022 evidence was downloaded separately and hashed before review: diagnostics `1f1b40f…`, launch `4c5235dc…`, CI probe `4b923caf…`, startup probe `cd21e241…`. Five startup variants all had `wait=258`, `exit_code=259`, prior suspend count 1, no marker, and thread `WaitReason=10`. This is a reproducible hosted symptom, not a verified internal root cause.

## Linux local pilot

```text
python -B -m research.linux_isolated_worker_v1.pilot --image curlimages/curl:8.5.0 --out build/linux-pilot-v1/report.json
```

The named image must already be local; the pilot uses `--pull never`. Final local status was `VERIFIED_LOCAL_PILOT` with 14/14 checks true. An earlier run failed to locate cgroup v1 paths and returned `HOLD`; the probe was corrected to observe the actual Docker Desktop cgroup version and rerun. Hosted CI deliberately supplies no image and must report `NOT_COVERED` rather than pull or fake isolation.

## Fresh checkout

CI performs an actual fresh checkout with `persist-credentials: false`, recomputes normal/repeat/optimized tests, gateway evidence, source mutations, layered integrity, integrity mutations, and the exact PR #1 replay. The Windows job uploads evidence before enforcing `status == VERIFIED`; any `PARTIAL`/`NOT_COVERED` result fails the gate.
