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

Full new exact-SHA clean replay and normal/repeat/-O reports will be appended only
after actual execution. Historical populations remain separate: v0 15, v02 11,
v03 3 KILLED/1 SURVIVED. New same-identity token diagnostics do not rewrite v03.

First token-probe attempt used an unwritable output location and exited1 without
an observation. It is retained as CONTROL_BROKEN, not a negative witness. The
corrected test creates an explicitly writable disposable output directory.
