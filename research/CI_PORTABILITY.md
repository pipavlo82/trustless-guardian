# v02 CI identity recovery

## Observed hosted result at f70ec99

**CI_BLOCKED / OS NOT_COVERED.** Exact head
`f70ec99a2cf8603527d1bbd399902e40694339b3`:
[push 40157967716](https://github.com/pipavlo82/trustless-guardian/actions/runs/40157967716)
and [PR 40157970822](https://github.com/pipavlo82/trustless-guardian/actions/runs/40157970822).
Both portable jobs passed; both Windows jobs failed before the OS campaign.

The existing linked-token query still returned WinError 1312. This time the
ephemeral reduction itself succeeded and was inspected: same user hash, medium
integrity, non-elevated, Administrators disabled, and only SeChangeNotifyPrivilege
present. `CreateProcessWithTokenW` then failed with **WinError 5 / Access denied**
at `CREATE_LIMITED_PROCESS`. No child enforcement witness was established.
The API failure is observed; its deeper runner-specific cause is not established.
Do not label these unexecuted mutations SURVIVED or CRASHED.

Raw logs, run metadata and both launch records are preserved in
`evidence/v02-hosted-f70-failure.zip`, SHA-256
`be104570f28926831215552f5187dd977b38d4b0962904acccb3fe217b87d8a9`.
No account provisioning, privilege enabling, desktop/security-policy changes,
persistent runner registration, or elevated-agent fallback was attempted. The
existing normal-user local Windows context remains the executable replay path.
For future CI recovery, independently audit the process-launch prerequisites or
provide an explicitly authorized non-elevated runner; do not turn this gate into
a skip. Subsequent documentation/evidence commits require their own exact-head CI.

## Reduction design and constraints

The previous WinError 1312 failure is preserved below and in immutable v0 archives.
v02 records the exact failing API stage. It first tries the existing linked limited
token. If its query specifically returns 1312, it may derive a new ephemeral token
from the existing runner token with `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE |
LUA_TOKEN)` and lower **only that new token's** integrity label to medium.

Before execution it requires the same user, no enabled Administrators group,
non-elevation, medium integrity, no AppContainer on the trusted orchestrator and
no remaining privilege except SeChangeNotifyPrivilege. It launches suspended and
checks the actual child's token again before resume. The confined agent and broker
still independently require their exact AppContainer SIDs, low integrity and zero
capabilities. No predicate is relaxed to obtain green checks.

No Windows account, new logon, persistent runner, UAC/security policy change or
privilege-enabling API is used. CreateProcessWithTokenW may require an already
available impersonation privilege; the launcher does not enable or obtain it.
Any unsuitable/missing token or launch failure remains NOT_COVERED and exits nonzero.
Portable CI is separate and never certifies OS enforcement.

The local reduction probe observed only SeChangeNotifyPrivilege remaining and an
unchanged parent token. That probe started non-elevated; it does not establish
hosted elevated-runner compatibility. Exact published-head Actions results and
raw launch metadata are the authority for that separate claim.

Alternatives considered: a pre-existing non-elevated interactive context (used
locally); an explicitly provisioned test account or dedicated hardened self-hosted
runner (not created/registered; would require approval). A broad elevated-agent
fallback or a green unavailable-OS skip is not permitted.

Sources: [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
and [CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw).

## Historical v0 hosted CI (preserved)

# Hosted CI portability

The first push and PR runs at `3c2ae0d67be725858139ff4e164d07d21abbb5c1`
passed the Linux portable job and failed Windows enforcement before the positive
agent witness could execute. The recorded Windows broker token was elevated
(high integrity). The agent-token guard refused to continue. The original error
did not record which child-token predicate failed; the elevated parent is an
observed environmental difference, not a fabricated complete diagnosis.

Run: https://github.com/pipavlo82/trustless-guardian/actions/runs/40153147825

The raw failure archive is `evidence/hosted-ci-initial-failure.zip`, SHA-256
`2b47ff570757319917aa22a693864603a0cfc7f269c914dd623052ab87033662`.
The hosted campaign reports **0 KILLED / 15 CONTROL_BROKEN**, with OS enforcement
and determinism NOT_COVERED. Those attempts are not combined with the successful
local 15-mutation campaigns. There was no failed deny followed by an observed
successful bypass: this was failed establishment of the execution environment.

`tools/ci_entry.py` preserves the non-elevated agent requirement. Under a normal
token it runs the unchanged validator directly. If the CI broker is already
elevated, it attempts only the user's **existing linked non-elevated token** and
checks the created broker's same-user identity, medium integrity and non-elevation
before resuming it. Missing or unsuitable linked tokens fail with NOT_COVERED.
It does not create accounts, request elevation, enable privileges, change UAC or
modify existing resource ACLs. Failure is not converted into a green skip.

This uses Microsoft's documented
[linked token handle](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_linked_token)
and [CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw).
The latter requires an already available impersonation privilege; Guardian does
not enable it or request it when absent. The normal local path does not use that API.

The child-token refusal now prints sanitized token diagnostics without the user's
SID. Local non-elevated entry replay passes normal/repeat/optimized policy and
OS tests. Hosted linked-token-path results must be read from the exact subsequent
CI run; they are not inferred from local success.

## Observed result of the limited-token attempt

At `1a8aa03bea916f62e26eb92b41374a10cf4c556b`, both push and PR portable
jobs passed. Both hosted Windows jobs remained blocked. The already elevated
runner could not establish the safe linked-token launch and returned **WinError
1312: a specified logon session does not exist**. No limited broker or OS witness
was claimed from that attempt. This is **CI_BLOCKED / OS NOT_COVERED**, not a
surviving Guardian mutation and not a green skip.

- [Push run](https://github.com/pipavlo82/trustless-guardian/actions/runs/40153591967)
- [PR run](https://github.com/pipavlo82/trustless-guardian/actions/runs/40153594033)

The same public HEAD was freshly cloned on the non-elevated Windows 11 host and
passed the complete normal/repeat/optimized OS suite and all 15 physical mutations
under `-O`. Its raw replay and the hosted error are preserved together in
`evidence/public-replay-v0.zip`. The source hashes match that commit exactly.

The remaining CI requirement is an available, independently verified non-elevated
Windows execution context. No administrator elevation, user-account provisioning,
UAC changes or security-setting changes are performed to obtain one. The current
workflow deliberately remains failing when that context is unavailable.
