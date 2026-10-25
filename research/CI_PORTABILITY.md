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
