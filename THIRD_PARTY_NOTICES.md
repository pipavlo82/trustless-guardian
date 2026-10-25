# Third-party boundaries

Guardian's original code and documentation are Apache-2.0, copyright 2026
pipavlo82. Upstream source code from the ten audited repositories is not copied,
vendored, relicensed or modified. See `research/source-lock.json` for exact
source and license identities and `research/SOURCE_AUDIT.md` for mixed-license scopes.

The test launcher downloads the official CPython 3.12.10 Windows embedded runtime
to ignored local build storage. It is not included in the repository or evidence
archive. CPython's PSF license and bundled dependency notices remain in the
extracted distribution. Download URL and exact SHA-256 are in `runtime-lock.json`.

Windows APIs are accessed through Python's standard-library ctypes. No Microsoft
source implementation is copied. GitHub Actions are referenced by commit; their
licenses remain with their respective projects. Apache's license text is included
as the standard license, not as original Guardian prose.
