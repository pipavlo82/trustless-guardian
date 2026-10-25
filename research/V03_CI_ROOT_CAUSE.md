# v0.3 hosted Windows diagnosis

**CI_BLOCKED / hosted OS enforcement NOT_COVERED.** The failing gate is retained.
Portable success does not establish Windows enforcement.

## Exact baseline evidence

At `d4df3adf1a23ecd4158e97d97cef5e1a155097dd`, the actual full logs and launch
records were retrieved from [push 40158551105](https://github.com/pipavlo82/trustless-guardian/actions/runs/40158551105)
and [PR 40158554139](https://github.com/pipavlo82/trustless-guardian/actions/runs/40158554139).
Both portable jobs passed. Both Windows jobs failed at CREATE_LIMITED_PROCESS:
CreateProcessWithTokenW returned WinError 5 before a child was created. The earlier
linked-token query returned 1312. No enforcement mutation executed there.

## Instrumented observation

At `7e348a7d4de75f57bb3d0193b8870aeb646b0a20`, read-only diagnostics ran in
[push 40197002146](https://github.com/pipavlo82/trustless-guardian/actions/runs/40197002146)
and [PR 40197005081](https://github.com/pipavlo82/trustless-guardian/actions/runs/40197005081).
Both retain portable success / Windows failure. Captured properties:

- Windows Server 2022, build 20348, Python 3.12.10; process in a job, session 2.
- Parent: primary token, high integrity, elevated, Administrators enabled,
  TokenElevationTypeDefault (1), no existing linked token (1312).
- SeImpersonatePrivilege **already enabled**. SeIncreaseQuotaPrivilege present but
  disabled; SeAssignPrimaryTokenPrivilege absent. No thread impersonation token.
- Newly restricted primary token: same TokenUser hash/session, medium integrity,
  non-elevated, Administrators disabled; only SeChangeNotifyPrivilege remains.
- NtQueryObject reports granted token-handle access 0x8b on both handles: includes
  QUERY, DUPLICATE and ASSIGN_PRIMARY required by CreateProcessWithTokenW.
- Secondary Logon service observed STOPPED before launch, query exit 0. That alone
  does not prove the cause: a stopped service can be demand-started by Windows.
- Actual command is 454 UTF-16 units, below the API's 1024-character limit.
- CreateProcessWithTokenW returns Access denied; `created_suspended=false`.

The established root failure is the hosted limited-token launch boundary, before
Guardian or its agent runs. **The specific internal Windows access check producing
WinError 5 remains UNVERIFIABLE.** Missing impersonation privilege, an oversized
command, or a failed AppContainer bypass test are not supported explanations.

## Safe alternatives and stopping boundary

An existing non-elevated Windows context works locally (Windows 11 build 26200,
medium integrity, non-elevated parent; the actual agent and broker are low-integrity,
zero-capability AppContainers). Existing linked-token use is unavailable hosted.

CreateProcessAsUser is documented to temporarily enable necessary privileges if
disabled. The hosted SeIncreaseQuotaPrivilege is disabled. That fallback was
therefore **not executed**, respecting the explicit prohibition on enabling
privileges to bypass restrictions. The own-restricted-token exception to
SeAssignPrimaryToken does not eliminate the quota-privilege issue.

No account, password, new logon, service-start command, desktop ACL change, UAC
change, elevated-agent fallback or persistent runner was used. A separately
authorized non-elevated Windows runner is still a possible next step. It has not
been provisioned. CI must remain nonzero until real enforcement executes.

Primary references: [CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw),
[CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw),
[restricted tokens](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).

## Repeated observation at the final tested code

At `2cae78637d9c596244deef007a13b83625653cb8`, [push 40199526037](https://github.com/pipavlo82/trustless-guardian/actions/runs/40199526037)
and [PR 40199529555](https://github.com/pipavlo82/trustless-guardian/actions/runs/40199529555)
again pass portable checks and fail Windows launch at the same API before child
creation. Exact diagnostics/logs are in v03-strict-cold-replay.zip. This does not
establish the unresolved internal Windows access-denial cause.
