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

## Reproduce the original reporting defect

In another disposable clone, retain the original production modules and add only
the new test harness. This is explicitly a modified test checkout, not the clean
baseline replay above:

```powershell
git clone https://github.com/pipavlo82/trustless-guardian.git guardian-v03-original
cd guardian-v03-original
git checkout --detach d4df3adf1a23ecd4158e97d97cef5e1a155097dd
git restore --source 5cd4c224109818bae0e6988af582948d9da430aa -- tools/v03_worker.py tools/v03_campaign.py
python -B tools/prepare.py
python -B tools/v03_campaign.py --witness post_write_failure --out build/original-write
python -B tools/v03_campaign.py --witness same_bytes --out build/original-same
```

The witness CLI exits zero when it collected a valid observation; inspect
`witness.json`: positive_ok=true and negative_ok=false reproduce the old behavior.
This exit code does not itself mean the security expectation passed. The full
campaign and validator fail on an unexpected outcome. For mutations, original and
restored negative_ok must both pass before a changed result can count as KILLED.

## Completed cold replay at 5cd4c224109818bae0e6988af582948d9da430aa

A new public clone started clean/detached at this exact revision. Full validator
exit 0: 22 units, 17 v0, 41 v02 and 21 v03 scenarios in normal/repeat/-O. The real
handle-inheritance witness passed. Historical v0 15 and v02 11 physical controls
were also rerun separately under -O: all KILLED, all other categories zero.
New v03 controls returned 3 KILLED / 1 SURVIVED / 0 CRASHED in both modes.
All 39 Python source digests match implementation revision 7e348a7. Stable
semantic outputs match the local replay byte-for-byte, including all three v03
modes. The checkout remains clean. This remains the same Windows machine.

Archive: `evidence/v03-cold-replay.zip`
SHA-256: `d0429923e35a836feb1ab6620d4860d5b0d572a348de3d45858a77d1ef427783`.
The archive includes actual commands, exit codes, process/host observations,
source hashes, both historical optimized populations and exact-head CI logs.
At this SHA the portable jobs pass and Windows jobs still fail before launch:
[push](https://github.com/pipavlo82/trustless-guardian/actions/runs/40197985141),
[PR](https://github.com/pipavlo82/trustless-guardian/actions/runs/40197990225).
Later evidence/report commits do not retroactively change this tested revision.
