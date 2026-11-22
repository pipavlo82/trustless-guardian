# Replay and challenge independent replay v1

All commands run from the repository root with the hash-locked dependencies in `requirements-auth-v1.txt`.

## Portable assessments

```text
python -B tools/guardian_regression_assessment_v1.py --out build/guardian-regression-v1/normal.json
python -B tools/guardian_regression_assessment_v1.py --out build/guardian-regression-v1/repeat.json
python -B -O tools/guardian_regression_assessment_v1.py --out build/guardian-regression-v1/optimized.json

python -B tools/auth_assessment_v1.py --out build/auth-v1/normal.json
python -B tools/auth_assessment_v1.py --out build/auth-v1/repeat.json
python -B -O tools/auth_assessment_v1.py --out build/auth-v1/optimized.json

python -B tools/replay_challenge_assessment_v1.py --out build/replay-v1/normal.json
python -B tools/replay_challenge_assessment_v1.py --out build/replay-v1/repeat.json
python -B -O tools/replay_challenge_assessment_v1.py --out build/replay-v1/optimized.json
```

Expected counts per mode are 177 inherited Guardian, 58 authentication, and 53 replay/challenge/receipt tests, all passing with no skip.

## Physical mutations

```text
python -B tools/replay_challenge_mutations_v1.py --out build/replay-v1/source-mutations.json --timeout 45
```

Expected final result: 19 KILLED and zero in every other classification.

## Integrity

Use the externally pinned SHA-256 from the exact candidate workflow:

```text
python -B tools/integrity_v3.py --policy-sha256 <exact-pin> --out build/integrity-v3/report.json
python -B tools/integrity_mutations_v3.py --policy-sha256 <exact-pin> --out build/integrity-v3/mutations.json
```

## Linux capability report

Only use an already-local image identity and do not pull:

```text
GUARDIAN_LINUX_V3_IMAGE=<already-local-image-or-id> python -B -m research.linux_isolated_worker_v2.pilot --out build/linux-v3/local.json
```

`NOT_COVERED` is the correct result when the exact pinned image is unavailable. Do not substitute another image or mock the container effects.
