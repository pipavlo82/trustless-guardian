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

New full cold-replay evidence will be appended after execution. Independent second
Windows environment and independent human review currently **NOT_COVERED**.
