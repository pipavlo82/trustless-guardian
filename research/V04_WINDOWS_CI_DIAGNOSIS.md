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

## Measured handle-rights isolation

At `6c015ce4d738890c0f64932e1bdfd9b845f61969`, push40206757070 and
PR40206761534 reproduced error5 with the original reduced handle (0x8b).
Duplicating the same reduced primary token with MAXIMUM_ALLOWED succeeded in
creating a suspended acceptable child. CREATE_NO_WINDOW did not distinguish the
outcomes. No child was resumed in this diagnostic.

At `6796f9a20aa931660b6af0a75618d404de35d5d5`, PR40206999147 isolated
individual handle rights, with the same reduced identity and process flags:

| Requested / granted handle access | Actual suspended creation |
| --- | --- |
| Original0x8b; fresh duplicate0x8b | WinError5 |
| 0x8f (+TOKEN_IMPERSONATE) | WinError5 |
| 0x18b (+TOKEN_ADJUST_SESSIONID) | Success; child security predicates pass |
| 0x9b (+TOKEN_QUERY_SOURCE) | WinError5 |
| 0xab (+TOKEN_ADJUST_PRIVILEGES) | WinError5 |
| 0xcb (+TOKEN_ADJUST_GROUPS) | WinError5 |
| 0x2008b (+READ_CONTROL) | WinError5 |
| MAXIMUM_ALLOWED, granted0xf01ff | Success; child security predicates pass |

This is a controlled causal distinction for the tested Windows Server2022
20348 context, not a claim about every internal Windows implementation. The
logon session existed (interactive type2, session2); primary token, medium IL,
same user, disabled Administrators and only SeChangeNotifyPrivilege were verified.
Read-only executable/directory access succeeded. The caller already had enabled
SeImpersonatePrivilege. No privilege was enabled, session changed or account made.

The launcher revision `f658c7863f1622ad8278fb68ea4ebbf927d87ea5` requests only
0x18b on a duplicate of the reduced token, compares its complete inspected
security properties with the original, creates a suspended child, verifies the
actual child's token, then resumes it. It does not use MAXIMUM_ALLOWED. This
repair grants access to a token handle in the trusted launcher, not new rights
to the confined agent. Actual enforcement results must be checked separately.

The public CreateProcessWithTokenW contract lists QUERY, DUPLICATE and
ASSIGN_PRIMARY. Our additional handle-access observation is environment-specific;
it is not a rewritten API specification. TOKEN_ADJUST_SESSIONID is distinct from
the SeTcbPrivilege required to change a token's session. The experiment neither
holds/enables SeTcbPrivilege nor calls SetTokenInformation(TokenSessionId).
See [token object access rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects).

The full v04 runner repeats every historical mutation population in all three
modes as well as the new population. Its aggregate budget is45 minutes under a
50-minute job; per-operation process/IPC timeouts are unchanged. A timeout still
fails the gate. This is a campaign scheduling budget, not additional execution
authority or a relaxed security predicate.

## Subsequent startup boundary (not an enforcement pass)

The f658c78 push40207380217 / PR40207385004 runs actually created and
validated the reduced child, then hit the30-minute validation watchdog. They
produced no Python-startup marker, child stdout/stderr or conformance reports.
The timeout is preserved as failure. A longer campaign budget cannot by itself
explain or repair the missing startup observation.

At `6e017085a4af1285e90d8151be8aca9565a304e6`, PR40210053593 ran a bounded
startup probe. cmd /d /q /c exit0, Python -I -S, and Python with inherited environment
all remained STILL_ACTIVE259 after a10-second wait, with no Python marker.
ResumeThread returned1 (the observed previous suspend count). Read-only process
inspection reported ThreadState5/Wait and WaitReason10/LpcReply. All children
were terminated and their termination observed. The actual validation launcher
now fails after20 seconds without its startup witness instead of waiting30 minutes.

WaitReason10 identifies a wait for a local-procedure-call reply; it does not
identify the server, missing right or Windows policy causing the wait. No claimed
CSRSS/desktop/runner-policy root cause is inferred from this number alone.
[Microsoft ThreadWaitReason definitions](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.threadwaitreason).
The named-pipe/ACL enforcement suite therefore remains NOT_COVERED on this hosted
environment at these revisions, despite successful token creation.

At `a4193593252864a7201b811682d47485ea3722f6`, push40210315112 and
PR40210319213 reproduced the blocker. Under the reduced token, read-only opens of
the actual WinSta0 station and Default desktop succeeded. Explicitly selecting
WinSta0\\Default did not change cmd or Python startup: previous suspend count1,
wait258/TIMEOUT, exit259/STILL_ACTIVE, no marker, thread wait10/LpcReply.
Each Python attempt now has a distinct fresh marker. No desktop ACL was changed.

**Current verdict: CI_BLOCKED / hosted enforcement NOT_COVERED.** Handle-rights
failure is resolved for the measured context; subsequent child startup remains
unresolved. Process creation, token inspection or a successful diagnostic exit
cannot substitute for actual AppContainer conformance execution. Portable jobs
pass. Both historical failures and bounded follow-ups remain in append-only
archives. A successful second-Windows enforcement replay remains NOT_COVERED.

Next bounded acquisition step: use an already authorized non-elevated Windows
runner according to docs/WINDOWS_REPLAY_PROTOCOL.md, or independently diagnose
the hosted startup wait with a Windows specialist. No account, service, persistent
runner, privilege enabling or machine-wide adjustment is authorized by this plan.
