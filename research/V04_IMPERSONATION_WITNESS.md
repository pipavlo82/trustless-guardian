# v0.4 impersonation witness

Historical v0.3 remains **3 KILLED / 1 SURVIVED**. Its cross-AppContainer client
requested SQOS=2 but the actual server thread token was identification (1).
That result is not rewritten, and equivalence is not inferred.

The new controlled diagnostic uses client/server threads under the same disposable
zero-capability, low-integrity AppContainer identity. No privileges are enabled.
Actual ImpersonateNamedPipeClient and independently implemented GetTokenInformation
observe levels 1, 2 and 3. Guardian accepts level1 and rejects levels2/3 with
IPC_IMPERSONATION_LEVEL. RevertToSelf is independently followed by ERROR_NO_TOKEN.
While impersonating, opening a disposable writable file fails at identification
and succeeds at levels2/3. Protected resource bytes stay unchanged throughout.

This is a real OS witness of the authentication-level contract, not a production
agent-to-broker execution bypass. The diagnostic uses the same identity and a
private pipe; the normal broker and agent use distinct AppContainer SIDs. It does
not establish higher-level token reachability in that normal deployment profile.
Remote delegation is not tested merely because a local level3 token is observed.

Removing the actual level check lets levels2/3 authenticate in this diagnostic;
restoring it restores refusal. A positive level1 control precedes both negative
levels and is repeated after source restoration. The independent oracle imports
no Guardian policy, broker, IPC or recovery code.

Classification: the historical test lacked a negative witness for the function;
the new diagnostic supplies one in a declared, narrower domain. No exploitable
production bypass is demonstrated. Full-profile higher-level reachability remains
**NOT_COVERED**; no universal environmental-unreachability/equivalence claim.

Primary references:
[ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient),
[impersonation levels](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels).
