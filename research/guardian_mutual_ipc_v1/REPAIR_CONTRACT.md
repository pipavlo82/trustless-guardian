# Bounded repair acceptance contract

Only A offline root admission, B replay protocol parity and C client I/O are repaired.
No execution grant or worker is introduced. The original protocol.py, cryptographic
primitives, PR7 source and all historical manifests remain unchanged.

The offline CLI now requires an independently selected policy file AND its digest,
plus independently supplied minimum policy and trust epochs. These floors are an
input contract; no persistent monotonic store or production root distributor exists.
Historical mode validates root state at capture and revocation effective time. A
later expired/revoked root can support historic evidence only. Current mode also
requires present root/policy validity. Neither mode authorizes tool execution. OS
process observations are not inferred from signatures.

Evidence JSON admission accepts exactly canonical integer-domain ASCII JSON, with
an optional single terminal LF. Existing original-v1 26-case captures are explicitly
selectable; repair-v1 requires 28 cases, including two cancellation observations.
The low-level verify_case API checks transcript consistency and root-at-capture,
not independently selected authorization; only the policy-admitting CLI/assess is
the authority-aware replay entry point. It must not be used as an authorization API.

Client pipe handles use FILE_FLAG_OVERLAPPED. Each operation waits at most 3000ms;
on timeout CancelIoEx targets its OVERLAPPED, followed by at most 1000ms completion
wait. Buffers survive until completion. No operation is accepted after timeout.
Completed local timeout exits91; inability to establish cancellation completion
exits90 without unwinding/releasing kernel-owned buffers. Exit90 is NOT a passing
cancellation witness. The outer disposable job supervisor remains defense in depth.
No wait/retry loop is introduced for connection failure.

Native diagnostics use one explicitly provisioned writable scratch file. Runtime
and root remain read-only; diagnostics are untrusted local observations, not signed
attestation. The original runtime ACL and private-key custody contracts are retained.

Windows reference: https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex
Cancellation request alone does not prove completion; the 995/completed-event witness
is required. Platform clock/scheduler hard real-time behavior is not claimed.

Production HOLD: lab fixture roots, no independently deployed authority distribution,
no end-to-end execution or human independent acceptance. No publication permitted.
