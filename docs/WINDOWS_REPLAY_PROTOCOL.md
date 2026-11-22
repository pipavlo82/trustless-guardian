# Independent Windows runner protocol

No infrastructure is registered by this document. Use an already authorized,
independently administered Windows machine with NTFS, Python3.12+, Git and network
access for the pinned Python runtime. Start an ordinary non-elevated shell. Do not
enable privileges, create accounts, relax UAC, or alter existing user/system ACLs.

Record physical/VM provenance separately from run count, Windows edition/build,
Python version, exact commit, initial worktree state and source inventory. Run
tools/ci_diagnostics.py and tools/v04_ci_probe.py to a new ignored build directory.
If already elevated without a safe existing context, stop the OS step as NOT_COVERED.
Do not treat a portable-only pass as permission to release.

Run the exact commands in research/V04_INDEPENDENT_REPLAY.md. The harness creates
only disposable Guardian roots/AppContainer profiles and records actual process
tokens, per-operation host bytes, pipe DACLs, journals, faults and exit codes.
Verify protected bytes after each denial/bypass; inspect process/pipe identities
and source-restoration SHA-256, not just totals. Unexpected crash/timeout/missing
output is CONTROL_BROKEN/CRASHED, never a successful negative result.

Keep raw output and independently compute archive/member SHA-256. Compare the
semantic reports across normal/repeat/-O while retaining machine-specific SIDs,
paths, timestamps and build information. Report legitimate environment differences
explicitly. Do not rename a repeated same-host run as cross-machine evidence.

Acceptance requires real non-elevated agent/broker AppContainers, actual byte
observations, valid positive controls and correctly classified physical mutations.
Keep the same-identity token diagnostic distinct from the normal distinct-SID
agent/broker deployment. Send results only through an explicitly authorized review
channel; this protocol does not authorize contacting anyone or provisioning runners.
