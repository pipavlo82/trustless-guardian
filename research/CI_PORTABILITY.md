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
