# v0.4 conformance results

Initial local execution: 25 portable unit tests; 15/15 new real Windows scenarios;
5/5 new physical mutants KILLED, no surviving/crashed/not-applied/broken controls.
These are finite laboratory observations, not production acceptance.

The starting d64 checkout ran the historical suites. Its first aggregate inventory
check correctly refused two new outer stdout/stderr files accidentally placed in
the checkout root. Those raw files and failed report are preserved. Moving only
those authored logs into ignored build/ restored the clean checkout; portable
normal/repeat/-O and all94 inventory entries then passed. Expectations or inventory
enforcement were not weakened. The failed aggregate is not called a clean pass.

Full exact-SHA clean replay and normal/repeat/-O results are recorded below.
Historical populations remain separate: v0 15, v02 11,
v03 3 KILLED/1 SURVIVED. New same-identity token diagnostics do not rewrite v03.

First token-probe attempt exited1 without an observation. Provisioning showed
an unwritable output location, but the inner exception was not captured, so that
diagnosis is an inference. It is retained as CONTROL_BROKEN, not a negative witness. The
corrected test creates an explicitly writable disposable output directory.

## Completed clean replay

Fresh public checkout: `6c015ce4d738890c0f64932e1bdfd9b845f61969`, detached,
empty porcelain status before and after. Windows11 Home10.0.26200 x64;
Python3.12.10, embedded agent runtime pinned by runtime-lock.json.
Command: `python -B tools/validate_v04.py --out build/cold` (exit0).
Actual sum of recorded outer command durations:1899.329 seconds. This is one
machine observation, not a performance benchmark.

| Population | Normal | Repeat | Python -O |
| --- | --- | --- | --- |
| Units | 25/25 | 25/25 | 25/25 |
| v0 scenarios | 17/17 | 17/17 | 17/17 |
| v02 scenarios | 41/41 | 41/41 | 41/41 |
| v03 scenarios | 21/21 | 21/21 | 21/21 |
| v04 scenarios | 15/15 | 15/15 | 15/15 |
| Direct OS bypass operations | 9 denied | 9 denied | 9 denied |
| Scratch positive / protected bytes | success / unchanged | success / unchanged | success / unchanged |

All four versioned semantic reports match byte-for-byte within their three modes.
v04 semantic SHA-256: `2aacb90649b87df9bef2332942024daa3a5048f2a949c3d9854c94b2701183dd`.
All11 pre-v04 evidence archives and112 then-current inventory entries verify.
The v03 harness-crash and v02 inherited-handle controls also exit0 with their
required observations. Source hashes, exact commands, exit codes and raw process
records are preserved in v04-cold-replay.zip; the separate observer reads bytes
and actual process tokens without importing Guardian policy/broker/IPC/recovery.

Every historical/new physical population was rerun in all three modes, with
byte-exact source restoration. Counts remain v0=15K/0S, v02=11K/0S,
v03=3K/1S, v04=5K/0S; crashes/not-applied/broken controls all0 in these completed
campaigns. Preliminary failed experiments above remain separately preserved.
