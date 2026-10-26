# v0.7 Windows portability investigation

Starting exact-head CI: push 40232997363 and PR 40233002150 at b72f7b9.
Both portable jobs passed; both Windows enforcement jobs failed. Actual failed
logs and the uploaded startup-probe artifact were retrieved and examined.

Current failure is **LIMITED_CHILD_STARTUP_NOT_OBSERVED**, not the old
CreateProcessWithTokenW/WinError 5. The API succeeds suspended, child token
inspection passes, ResumeThread returns 1, but Python startup is not observed.
The ephemeral reduced token is medium integrity, non-elevated, same base user,
administrators disabled, no added privileges, and preserves its measured attributes.

Five safe diagnostic variants also failed to finish within their bounded waits:
cmd, isolated Python, Python with inherited environment, cmd on current desktop,
Python on current desktop. Each returned wait=258, exit=259 while still running,
with no marker; they were terminated after observation. The limited token could
open the current window station/desktop for read. Explicitly selecting that
desktop did not establish startup. Thread queries reported state 5/reason 10.
These facts do not prove a particular loader, logon, desktop or security-policy
root cause. That deeper cause remains unresolved.

No UAC change, privilege enablement, persistent account/runner, machine policy
change or relaxed AppContainer predicate was attempted. The Windows enforcement
workflow is byte-identical to its previous steps. Only portable CI selects v07.
Unavailable enforcement remains CI_BLOCKED / NOT_COVERED.

Local environment is Windows 11 Home build 26200, non-elevated, host Python 3.12.10;
live worker Python 3.11.16; deterministic worker embedded Python 3.12.10. Repeated
runs on this machine do not establish cross-host portability. No second Windows
machine was safely available. Use the existing [independent runner protocol](../docs/WINDOWS_REPLAY_PROTOCOL.md)
and the [preview prerequisites](../docs/DEVELOPER_PREVIEW.md); do not register a
persistent runner or change security settings to make a check green.
