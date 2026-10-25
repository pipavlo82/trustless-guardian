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

The v0.6 laboratory adapter executes an existing Hermes Agent installation
(MIT, copyright 2025 Nous Research), pinned at
f7c79efbac19ae18e8dee7c79a4e4c0935299b5f. Program/dependency files are copied only
into ignored disposable runtime storage; no Hermes code is vendored here.
Its LICENSE and the dependencies' distribution metadata remain in that local
copy. The copied Python 3.11 runtime retains its original license notices.
The source/dependency hash inventory is evidence, not a relicensing statement.

Codex CLI is an installed external runtime, not redistributed by Guardian. The
adapter uses the normal authorized ChatGPT login without copying credentials.
No claim is made that this experimental transport is an official Hermes or
OpenAI integration. Cursor/Grok identification does not establish runtime support.
