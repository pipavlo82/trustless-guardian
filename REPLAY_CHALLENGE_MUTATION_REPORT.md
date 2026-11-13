# Replay and challenge mutation report v1

The final physical source-mutation population has 19 cases. Every mutant is applied in a disposable copy, the named control is executed, and the original bytes are restored and rechecked.

Final Windows result: 19 KILLED, 0 SURVIVED, 0 NOT_APPLIED, 0 CRASHED, 0 CONTROL_BROKEN.

Final WSL Linux result: 19 KILLED, 0 SURVIVED, 0 NOT_APPLIED, 0 CRASHED, 0 CONTROL_BROKEN.

The population covers:

- challenge session, message, resource, consumption, and atomic single-use binding;
- durable-state failure refusal and admission identity;
- scope, worker, image, trust-version, and grant-key binding;
- committed-state persistence and ambiguous-outcome no-retry behavior;
- independent proof that a Docker CLI result without an observed container identity is not execution;
- receipt signature, type discipline, lifecycle consistency, and evidence hashing.

Historical development result: the first 16-case campaign produced 15 KILLED / 1 SURVIVED. The survivor was `challenge-atomic-consume`; the earlier end-to-end concurrency test was stopped by the preceding inspection guard and therefore did not witness the atomic update itself. A separate pre-inspected race test was added. The next 16-case campaign killed all 16. Later source hardening added three more cases for a final population of 19.

These are mutation controls for the named local source and tests. They do not establish universal security, production isolation, external review, or completeness against unmodeled defects.
