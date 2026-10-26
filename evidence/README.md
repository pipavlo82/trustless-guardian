# Evidence and reproduction

## v04 additive evidence

- `v04-originals-and-diagnostics.zip`: `31433ba3108405008e616e3b4cdac00b5d3e40964ae81ec140a9d7dcdc7e2f28` (5,519 members).
- `v04-cold-replay.zip`: `8d68cb94cccd6eccbe61b25c5ecfb6c89b2f62f33bda5ee1ea8ef1df338f445b` (14,236 members).
- `v04-hosted-diagnostics.zip`: `adbc7cfda0070a35dbb7af70c074671c602d6dfabdb621bf494fff9cb98ee95b` (32 members).

The first retains the starting inventory failure caused by authored root logs,
its corrected portable replay, original exact-production-byte defect witnesses,
failed token-probe control and early hosted diagnostics. The second preserves
the complete clean6c015ce replay, all normal/repeat/-O campaigns and raw byte/token
observations. The third retains later hosted failures and source/aggregation tools.
Historical v0/v02/v03 archives are unchanged. No crash is counted as a mutation kill.
New v04 mutation counts are5/0, separately from historical v03's3/1.

```powershell
python -B tools/evidence.py verify evidence/v04-originals-and-diagnostics.zip
python -B tools/evidence.py verify evidence/v04-cold-replay.zip
python -B tools/evidence.py verify evidence/v04-hosted-diagnostics.zip
python -B tools/integrity.py
python -B tools/validate_v04.py --out build/review-v04
```

See [v04 replay](../research/V04_INDEPENDENT_REPLAY.md) for exact source attribution.
Archive hashes establish byte integrity, not independent honesty of the host.

## v02 additive evidence

`v02-local-replay.zip` and its companion inventory preserve the pre-change v0
baseline, full fresh replay at `d6ee623eecaeffe6aaf079986af84afc2a2d3660`, the
same 11-mutant campaign under `-O`, and integrated handle-witness replay at
`3eb3a15a68b4dc00b07a0ef2e8d04320888f52e3`. Raw process outputs, exit codes,
per-attempt host byte observations, native probe failures, source correspondence
and development failures are separate members. Source code hashes corroborate
the final unchanged enforcement modules. A later CI-dispatch fix affects only
the elevated launcher's choice of validator; its expression controls are included.

Archive SHA-256:
`6c91855b06983f4d7bb8e28a933f5aaed05ea43f7cd210bc066eadf74ba05922`.
The companion `v02-final-corroboration.json` records final source hashes and a
separate replay of the CI-dispatch controls with full literal subprocess argv
(the archive's first dispatch report used an abbreviated description in argv).

The archive is additive: all four v0 archives stay byte-identical. Public
development-probe derivatives redact personal SIDs and record both original and
derivative hashes; original local files are retained. Package SIDs are disposable.
The intermediate development run made while source was changing is not used as
exact-revision evidence. Normal and optimized runs of the same mutant population
are not separate kills. CI execution must be verified at its exact published HEAD.

`v02-hosted-f70-failure.zip` separately preserves the first v02 hosted push/PR
attempt at `f70ec99a2cf8603527d1bbd399902e40694339b3`. Reduced token inspection
succeeded; child creation failed with WinError 5. It is not an OS-test success.
SHA-256: `be104570f28926831215552f5187dd977b38d4b0962904acccb3fe217b87d8a9`.

```powershell
python -B tools/evidence.py verify evidence/v02-local-replay.zip
python -B tools/integrity.py
python -B tools/validate_v02.py --out build/replay-v02
python -B -O tools/v02_mutations.py --out build/replay-v02-optimized-mutants
python -B -O tools/handle_control.py --out build/replay-v02-optimized-handle
```

See [machine summary](../research/V02_SUMMARY.json),
[measured results](../research/CONFORMANCE_RESULTS.md), and
[limitations](../research/LIMITATIONS.md). A hosted token failure remains a failed
OS gate; portable tests are never evidence of Windows confinement.

## Historical v0 evidence (preserved)

`local-run-v0.zip` preserves the original local normal/repeat/optimized logs,
the first 15-mutation campaign, selected upstream checks (including failed
attempts), original prototype tests and source-preservation hashes. Its companion
inventory lists every member's exact SHA-256 and size plus the archive SHA-256.
Historical archives are not overwritten. CPython runtime and mutation checkouts
are excluded; original observations and command outputs are retained.

```powershell
python -B tools/evidence.py verify evidence/local-run-v0.zip
python -B tools/evidence.py verify evidence/fresh-replay-v0.zip
python -B tools/integrity.py
python -B tools/validate.py --out build/independent-replay
```

The archive's `validation/report.json`, `mutations/report.json`, lab summaries,
individual process/worker records, separate-verifier commands and stdout/stderr
are the machine-readable evidence. `*.semantic.json` (inside each lab directory
as `semantic.json`) excludes incidental run identities and timing, retaining
authorization outcomes and observed byte transitions. It is compared byte for byte.

Package SIDs are disposable identities; personal user SIDs are represented only
by hashes or placeholders. Evidence contains local paths and Python versions,
but no passwords, production API keys, cookies or private signing credentials.
Logs are unsigned host observations. A reader must not treat their internal
hashes as independent attestation of an honest host.

Fresh-checkout and hosted CI replay evidence is additional to this first archive.
See `research/CONFORMANCE_RESULTS.md` and subsequent replay manifests for exact
tested revisions and remaining limitations. A new checkout on the same computer
is independent of the worktree, not an independent external security review.

`fresh-replay-v0.zip` contains the complete optimized campaign at `977f9b3`,
the complete post-ownership-control campaign at `d5812be`, and post-run Git-blob
corroboration of every recorded source hash. Its inventory gives exact archive
and member hashes. The original archive remains byte-identical.

The local archive SHA-256 is
`9aaac972c3c54f0bd784e801f7dc31f046bf6e7d417b8e8a6b959fd3f8ea0255`.
See [machine summary](../research/SUMMARY.json) for both archive identities.

`hosted-ci-initial-failure.zip` separately preserves the initial hosted Windows
token-establishment failure and broken controls. It does not supersede the local
success archive or count as a successful OS campaign.

`public-replay-v0.zip` preserves a complete fresh public-clone replay at
`1a8aa03bea916f62e26eb92b41374a10cf4c556b`, including 15 optimized mutations,
and the separate hosted limited-token failure. Its SHA-256 is
`ea2dcd9e99a87e1e4f1c0ef9942a23129dde2a634273d695f20a1fd53e53a51e`.

## Published-source fresh replay

A fresh clone fetched from GitHub at
`f70ec99a2cf8603527d1bbd399902e40694339b3` passed the complete suite:
20 unit tests per mode, 17 v0 scenarios per mode, 41 v02 cases per mode,
15 historical and 11 new physical mutations (separate populations), the
inheritable-handle witness, all then-present archives and 68 inventory entries.
Normal/repeat/-O v02 semantic output again has SHA-256
`bf942e4341ceac799d382be75dfa0cb463da27cf79aae4ebc102899b74cea6f0`. Source hashes match all final
enforcement/test/launcher Python files. Later changes are documentation, evidence
and inventory only. This is a new checkout on the same non-elevated Windows host,
not a separate organization or hosted-runner result.

Archive: `evidence/v02-public-f70-replay.zip`; SHA-256
`6558b3ee18bde4a938872fe90f27303955c7f8c6cf7613deefb02ea3b8749412`. Commands, exit codes, raw observations and
source correspondence are retained. Both hosted attempts at this code commit
remain independently **CI_BLOCKED** as documented in CI_PORTABILITY.

## v03 additive evidence

The starting d4 baseline, original post-write/same-byte observations, two failed
initial harness expectations, read-only native pins and hosted launch failures
are preserved in v03-baseline-and-audit.zip. v03-local-replay.zip preserves the
complete working-checkout validation; it is not called a clean checkout.
v03-cold-replay.zip preserves the public clean 5cd4c22 replay and extra optimized
historical mutation runs. Each ZIP has a separately verified member inventory.
Actual named-pipe SDDL observations include Windows SIDs; these identify OS
principals, not credentials. No API tokens, passwords or private keys are included.

- `v03-baseline-and-audit.zip`: `2f25d00fa0ad0a7ca885aedff08014a503c01f68428e3fec5b46596753193a32`
- `v03-cold-replay.zip`: `d0429923e35a836feb1ab6620d4860d5b0d572a348de3d45858a77d1ef427783`
- `v03-local-replay.zip`: `db0b44bfb239037c133e093ec3d010b94860fedf54f1517df782777ace5df25d`

The seven pre-v03 archives and their inventories remain byte-identical.

Final strict harness replay at 2cae78637d9c596244deef007a13b83625653cb8:
`v03-strict-cold-replay.zip` SHA-256 `c5db6552344eede8db5fbab1ed5f6b4c472ba25cee63b9ed7b34f41e7b324b05`.
Earlier v03 archives are also unchanged; this is additive.
