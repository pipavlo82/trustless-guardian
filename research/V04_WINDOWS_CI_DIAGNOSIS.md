# v0.4 Windows CI diagnosis

Starting exact-head runs: [push40200749203](https://github.com/pipavlo82/trustless-guardian/actions/runs/40200749203)
and [PR40200753299](https://github.com/pipavlo82/trustless-guardian/actions/runs/40200753299).
Actual logs/artifacts were retrieved again. Portable passed; Windows failed at
CreateProcessWithTokenW with WinError5 before child creation. This identifies a
failing boundary, not the undocumented internal access check.

New bounded diagnostic tools/v04_ci_probe.py reads TokenStatistics authentication
ID and LsaGetLogonSessionData, token rights/type/IL/session/privileges, and attempts
read-only executable/directory opens under the reduced identity. It compares the
existing token handle with a DuplicateTokenEx MAXIMUM_ALLOWED handle and two
CREATE_SUSPENDED flag sets, with/without CREATE_NO_WINDOW. Any created child is
inspected and terminated without ResumeThread. No credential logon, account,
privilege enabling, service/UAC/system-policy/ACL change is requested.

The diagnostic runs only when the caller is already elevated and already has
enabled SeImpersonatePrivilege. Local non-elevated execution records that those
hosted-only attempts are unavailable. A diagnostic exit0 is not an enforcement
pass. The subsequent actual enforcement gate remains required and nonzero on
unavailable context. Hosted results for this new diagnostic are pending publication
at this report's initial revision; subsequent evidence sections record actual runs.

No CreateProcessAsUser fallback that temporarily enables the disabled quota
privilege is used. No persistent runner is registered. Independent Windows replay
protocol: [docs/WINDOWS_REPLAY_PROTOCOL.md](../docs/WINDOWS_REPLAY_PROTOCOL.md).

Primary references:
[CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw),
[DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex).
