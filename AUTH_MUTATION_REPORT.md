# Independent Authentication Mutation Report

## Method

The authentication campaign changes real source bytes in a disposable copy. Every row requires:

1. a passing targeted baseline;
2. exactly one applicable mutation specification;
3. a failing mutant test to count as `KILLED`;
4. exact restoration of the original bytes; and
5. a passing restored control.

A timeout or unexpected exit is `CRASHED`, not a kill. A missing source pattern is `NOT_APPLIED`. A bad baseline or restoration is `CONTROL_BROKEN`.

## Local result

The final machine-readable result is `build/auth-v1/source-mutations.json` during replay and is summarized in `verification/independent-auth-linux-v1.json` in the committed evidence.

Covered predicates include JWT role/request/wallet/key revocation, trust-root availability/staleness, SIWE resource/registry binding, MCP scope/request binding, authorization ownership/role, execution-grant signature/request binding, and replay rejection.

The integrity campaign separately mutates frozen files, manifests, authorized additions, policy, bootstrap workflow presence, and unexpected files. Historical and new-source mutations are not pooled into a score; each gate must have zero survivors and healthy controls.
