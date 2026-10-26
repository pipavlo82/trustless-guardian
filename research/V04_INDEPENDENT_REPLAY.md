# v0.4 independent replay protocol and evidence

Independent here describes a separate oracle implementation and process. Same
physical host/engineering author is not an independent reviewer or second machine.
The observer imports neither Guardian policy, broker, IPC nor recovery code.
It uses ctypes Win32 token queries and directly reads protected bytes. Expected
fault outcomes are declared independently of returned implementation observations.

Use the exact published revision whose report is being reviewed:

```powershell
git clone https://github.com/pipavlo82/trustless-guardian.git
cd trustless-guardian
git checkout --detach <reviewed-full-SHA>
python -B tools/integrity.py
python -B tools/validate_v04.py --out build/review-v04
```

Full runner executes historical and new scenarios normal/repeat/-O, and each
historical/new mutation population in normal/repeat/-O with separate reports.
It retains stdout/stderr, exact argv/return codes, source hashes and semantic JSON.
`--portable` executes unit/integrity/archive checks only and establishes no OS claim.
Use new output paths; place outer redirected logs under ignored build/ or outside
the checkout. Do not regenerate inventory to accommodate generated output.

Initial witnesses against exact d64 production bytes reproduce both defects;
new harness files are expressly additions to that disposable test copy. That
original control is not described as an untouched whole-checkout replay.

Completed cold-replay evidence is recorded below. Independent human review remains
**NOT_COVERED**; hosted Windows results are separately versioned in the CI report.

## Completed local cold checkout

The complete command above executed at
`6c015ce4d738890c0f64932e1bdfd9b845f61969` with empty Git status before
and after, returning0. See V04_CONFORMANCE_RESULTS.md for measured counts.
All production Guardian modules and all functional scenario/oracle/mutation
modules remain byte-identical in the later CI-launcher changes. The only Python
differences to existing files are tools/ci_entry.py and tools/v04_ci_probe.py;
tools/v04_startup_probe.py is an additional hosted diagnostic. These concern hosted
token creation/diagnostics and campaign scheduling. Those require their own
hosted observations and are not silently attributed to this local checkout.

Hosted Windows Server2022 build20348/Python3.12.10 supplied genuine token/startup
diagnostics on separate GitHub runner environments. It did not execute a successful
enforcement campaign: all final bounded startup candidates waited for LPC reply
and were terminated. This is not cross-machine enforcement verification. A second
successful Windows enforcement replay and independent reviewer remain NOT_COVERED.

Archives: v04-originals-and-diagnostics.zip (starting failure and original defects),
v04-cold-replay.zip (complete clean local replay), v04-hosted-diagnostics.zip
(subsequent failed hosted runs, exact source correspondence and aggregation tools).
Every member is SHA-256 inventoried; verify each with tools/evidence.py.
