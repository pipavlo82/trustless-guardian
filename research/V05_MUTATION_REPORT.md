# v0.5 physical mutation population

The initial executed campaign killed **4 / 4** physical mutants, with **0
SURVIVED, 0 CRASHED, 0 NOT_APPLIED, 0 CONTROL_BROKEN**. Final replay reports
record subsequent modes separately. These are scripted OS-control mutants,
not real-agent mutation coverage.

| Physical change in disposable copy | Distinguishing witness |
|---|---|
| Remove native resource-ID comparison | Wrong-resource proposal modifies the broker resource instead of refusing |
| Remove native actor membership check | Action proceeds after trusted provisioner removes the actor |
| Return NOT_EXECUTED after possible write | Actual changed bytes disagree with definitive non-execution |
| Grant agent write on the disposable source ACL | Direct native write succeeds and host bytes change |

Each mutant runs original, changed and byte-restored implementations. The
original/restored full demo must pass. The changed run must retain valid ALLOW,
receipt/identity checks and scratch-write control, then fail the targeted
negative check. Missing output, timeout or crash is not KILLED. Source hashes
and exact restoration are recorded. The ACL variant changes only a newly created
laboratory resource, never an existing user file or system ACL.

The v0 15, v0.2 11, v0.3 3 KILLED / 1 SURVIVED, and v0.4 5 KILLED populations
remain separate historical experiments. The v0.3 survivor is not reclassified.

```powershell
python -B tools/v05_mutations.py --out build/mutations
python -B -O tools/v05_mutations.py --out build/mutations-optimized
```

Do not infer new defects in the unchanged broker from intentionally weakened
copies. These controls measure whether the demonstration detects those changes.

The first aggregate development replay retained **3 KILLED / 1 CRASHED** in
optimized mode: the mutated post-write-outcome run failed its initial ALLOW
setup (`BROKER_START_FAILED`; the server recorded an IPC timeout). This was not
a semantic kill. Normal/repeat each recorded 4 KILLED. The report is preserved.
The new demo gives only its laboratory connection an 8-second bounded readiness
budget, allowing the independent observer to run before client connection;
production IPC/authorization code remains unchanged. The classifier now also
requires the specific forbidden byte transition or false NOT_EXECUTED response
before calling any changed run KILLED. Transport failure alone is insufficient.

The subsequent optimized development run retained **3 KILLED / 1 CONTROL_BROKEN**:
the resource-binding original positive had changed bytes but lost its IPC reply.
It was correctly disqualified even though the mutated witness distinguished the
boundary. The final demo uses an explicitly separate 8-second lab I/O budget,
including response and ACK (historical budgets were 3000ms and 700ms). A 40-second
child-process bound remains. No request is retried and no timeout becomes PASS.
Concurrent disk/scheduling pressure is a plausible contributor, not a proven
root cause. Native IPC authorization, framing and cancellation are unchanged.

Final clean replay at `f2a25fc8ed2d1de6cb84e661d77eeeb039d5c3ec` independently
executed all four v0.5 mutants in normal, repeat and optimized mode: **4 KILLED /
0 SURVIVED / 0 CRASHED / 0 NOT_APPLIED / 0 CONTROL_BROKEN in each mode**.
Each kill contains the specific changed byte transition or false non-execution
response, valid positive controls, and byte-exact restoration. These are four
distinct mutations, not twelve distinct boundaries.

The earlier cold checkout at `d2d177ae2c527ad67fd3ffaac7a2cc15a03202cb` recorded
2K/2CB normal, 3K/1CB repeat and 1K/3CB optimized. It remains a failed replay.
Historical v0.4 repeated controls also retain failures in the serial replay;
see the exact table in [security results](V05_SECURITY_RESULTS.md).
