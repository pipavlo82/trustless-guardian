# Independent Authentication and Isolation Replay

All commands start at the repository root. They use disposable keys and local synthetic targets only.

## Dependency bootstrap

Windows PowerShell:

```powershell
py -3.12 -m venv build/auth-venv-v1
build/auth-venv-v1/Scripts/python.exe -m pip install --require-hashes -r requirements-auth-v1.txt
```

Linux:

```bash
python3.12 -m venv build/auth-venv-v1
build/auth-venv-v1/bin/python -m pip install --require-hashes -r requirements-auth-v1.txt
```

## Authentication and inherited invariants

```bash
python -B tools/auth_assessment_v1.py --out build/auth-v1/normal.json
python -B tools/auth_assessment_v1.py --out build/auth-v1/repeat.json
python -B -O tools/auth_assessment_v1.py --out build/auth-v1/optimized.json
python -B -m unittest discover -s tests -q
python -B -m unittest discover -s tests -q
python -B -O -m unittest discover -s tests -q
```

The authentication assessment records test identifiers, dependency versions, and source SHA-256 values. It does not record private keys, signatures, JWTs, SIWE messages, or bearer tokens.

## Mutation campaigns

```bash
python -B tools/auth_source_mutations_v1.py --out build/auth-v1/source-mutations.json
python -B tools/integrity_mutations_v2.py \
  --policy-sha256 POLICY_SHA256_FROM_PINNED_WORKFLOW \
  --out build/integrity-v2/mutations.json
```

Each source mutation has a passing baseline, a physically edited mutant, exact byte restoration, and a passing restored control. Results remain split into `KILLED`, `SURVIVED`, `NOT_APPLIED`, `CRASHED`, and `CONTROL_BROKEN`.

## Versioned integrity

```bash
python -B tools/integrity_v2.py \
  --policy-sha256 POLICY_SHA256_FROM_PINNED_WORKFLOW \
  --out build/integrity-v2/report.json
```

The v2 policy freezes the exact 273-file PR #4 inventory, preserves every prior SHA-256, identifies the one authorized replacement, and separately pins PR #5 additions. The policy digest is independently pinned by the PR #5 workflow.

## Linux containment

Use only an image already present locally and identify it explicitly. The pilot never pulls:

```bash
python -B -m research.linux_isolated_worker_v2.pilot \
  --image curlimages/curl:8.5.0 \
  --out build/linux-v2/report.json
```

The local evidence used cached image ID `sha256:08e466006f0860e54fc299378de998935333e0e130a15f6f98482e9f8dab3058`. A host without that pinned local image reports `NOT_COVERED`.

## Fresh-checkout replay

```bash
git clone https://github.com/pipavlo82/trustless-guardian.git guardian-pr5-replay
cd guardian-pr5-replay
git checkout COMMIT_SHA_FROM_PR5
git status --short
```

Then run the dependency, authentication, inherited-invariant, integrity, and platform commands above. GitHub Actions performs the same checkout with credentials persistence disabled.
