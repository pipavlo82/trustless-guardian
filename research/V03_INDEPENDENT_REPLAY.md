# v0.3 reproduction record

The baseline was freshly cloned from the public repository and checked out at
`d4df3adf1a23ecd4158e97d97cef5e1a155097dd`. Its complete v02 validator passed.
The implementation revision is `7e348a7d4de75f57bb3d0193b8870aeb646b0a20`.
Final clean-checkout results and evidence archive identities are recorded in the
adjacent machine-readable `V03_SUMMARY.json` and follow-up replay evidence.

## Commands

Run from an existing non-elevated Windows user context; Python 3.12+, Git and NTFS.
No elevation, account provisioning or security-policy change is needed for the
observed local path. The pinned embedded Python runtime is independently hashed
by tools/prepare.py. The validator creates only disposable guardian-lab-* roots.

```powershell
git clone https://github.com/pipavlo82/trustless-guardian.git guardian-v03-replay
cd guardian-v03-replay
git checkout --detach <exact-tested-sha-from-V03_SUMMARY>
git status --porcelain
python -B tools/integrity.py
python -B tools/validate_v03.py --out build/fresh-v03
```

The validator includes normal/repeated/-O units; v0/v02/v03 real OS campaigns;
the parent-handle control; separate historical and new physical mutations;
normal and optimized v03 mutation runs; archive hashes and source inventory.
Every subprocess's exact arguments, exit code, stdout/stderr and timing is saved.
The v03 mutant survivor remains reported and `coverage_complete=false`.

Targeted commands after `python -B tools/prepare.py`:

```powershell
python -B tools/v03_campaign.py --out build/v03-normal
python -B tools/v03_campaign.py --out build/v03-repeat
python -B -O tools/v03_campaign.py --out build/v03-optimized
python -B tools/v03_mutations.py --out build/v03-mutations
python -B -O tools/v03_mutations.py --out build/v03-mutations-O
python -B tools/v03_campaign.py --witness post_write_failure --out build/post-write
python -B tools/v03_campaign.py --witness same_bytes --out build/same-bytes
python -B tools/ci_diagnostics.py --out build/runner-token.json
```

Semantic JSON compares stable scenario results; ephemeral paths, package SIDs,
PIDs, file IDs, timings and raw process output are preserved but are not required
to be byte-identical. The exact source hashes, original failures and archive
inventories permit inspection of what actually ran. No historical archive is
regenerated or replaced.

The host witness is a separate process from both confined principals and reads
actual protected bytes after attempts. The existing independent receipt verifier
also reruns in v02. These are engineering independence boundaries, not an external
human reviewer or second physical Windows machine; both remain NOT_COVERED.
