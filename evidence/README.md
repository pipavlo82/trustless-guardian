# Evidence and reproduction

`local-run-v0.zip` preserves the original local normal/repeat/optimized logs,
the first 15-mutation campaign, selected upstream checks (including failed
attempts), original prototype tests and source-preservation hashes. Its companion
inventory lists every member's exact SHA-256 and size plus the archive SHA-256.
Historical archives are not overwritten. CPython runtime and mutation checkouts
are excluded; original observations and command outputs are retained.

```powershell
python -B tools/evidence.py verify evidence/local-run-v0.zip
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
