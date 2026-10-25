# Physical mutation report

Executed campaign: **15 KILLED, 0 SURVIVED, 0 CRASHED, 0 NOT_APPLIED,
0 CONTROL_BROKEN**. These counts apply only to the listed physical mutations.
Unexecuted controls are not included as kills or implied coverage.

Each variant is a disposable source copy. The runner executes an allowed positive
control and isolated negative witness against the original source, changes one
physical condition or operation, reruns both, restores the exact original bytes,
and reruns both again. Child processes use real AppContainer tokens. A kill requires
the mutated negative witness to **actually change protected file bytes** while
its positive control still works. The runner records stdout, stderr, exit codes,
source digests and restored-byte equality.

| ID | Physical change | Isolated distinguishing witness |
| --- | --- | --- |
| actor | Remove actor comparison | Wrong declared actor writes |
| action | Remove action comparison | Delete-labelled request causes forbidden replacement |
| resource | Remove resource comparison | Other symbolic resource authorizes sample write |
| scope | Remove scope comparison | Arbitrary scope authorizes write |
| version | Remove version comparison | Other policy version authorizes write |
| expiry | Remove expiry comparison | Expired request writes |
| replay | Remove nonce validation condition | Empty nonce writes; this witness isolates nonce shape |
| evidence | Remove evidence-shape guard | Extra unvalidated evidence field silently accepted |
| precondition | Remove prior-byte digest comparison | Wrong pre-state claim writes |
| content | Remove content restriction | Unapproved bytes written |
| policy_pin | Remove trusted policy digest check | Changed max_bytes policy with same version accepted |
| resource_identity | Remove file identity check | Replacement file with same prior bytes is written |
| enforcement | Execute regardless of decision | DENY record accompanies actual unauthorized write |
| nonce_consumption | Remove durable INSERT | Previously used nonce writes on second request |
| acl | Replace protected read/execute grant with full access | Direct agent write succeeds outside gateway |

The nonce-shape and nonce-consumption controls are separate; removing one
policy-level replay check may still encounter SQLite uniqueness enforcement.
This campaign does not claim that every possible replay mutant is killed.
The evidence-shape witness keeps a valid prior digest so it reaches the intended
guard without crashing on a missing key.

The ACL mutant deliberately grants write only inside its disposable copied lab.
The low-integrity label on the disposable file makes DACL enforcement observable:
the baseline denies a direct write, the mutant allows it, restoration denies it.

CRASHED means missing/failed mutant execution, never a semantic kill.
CONTROL_BROKEN means a failed original/restored control or failed positive
control. NOT_APPLIED means no unique physical edit could be established.
Unit tests exercise these classifier distinctions independently.

Not mutation-covered: broker hard-link/reparse guards, all Win32 failure paths,
concurrent brokers, SQLite crash recovery, Windows kernel/AppContainer internals,
production IPC and native ReceiptOS/VECA adapters. No universal mutation score is claimed.
