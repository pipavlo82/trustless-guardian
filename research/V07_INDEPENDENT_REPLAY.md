# v0.7 independent cold replay

Implementation commit: `0d45aae8cfed7e06f9f2c742af0ffbf768b2bd79`.
Starting remote branch: `b72f7b920d362d866ed0680d73b8f12a53ff37dc`.
Protected main: `aaa941cf3566a6931cba539e4d8147d940459171`.

A fresh `git clone --no-local` was used with a clean implementation checkout.
The runtime copy is independently rehashed against the preserved 14,114-file pin;
this is not independent dependency bootstrap. Exact source/commands/versions,
return codes and stdout/stderr are retained by the validation drivers.

```powershell
python -B tools/validate_v07.py --runtime build/guardian-lab-hermes-runtime --out build/cold-v07
python -B tools/validate_v04.py --no-mutations --out build/cold-v04
python -B tools/validate_v05.py --no-mutations --out build/cold-v05
python -B tools/validate_v06.py --runtime build/guardian-lab-hermes-runtime --out build/cold-v06
python -B tools/v07_integrity.py
python -B tools/integrity.py
```

Each versioned runner records requested normal/repeat/-O outcomes. New physical
mutants are rerun in three modes separately from historical mutation populations.
Only semantic check maps are compared byte-for-byte; random SIDs, PIDs, inference
output, clocks and absolute paths are not claimed byte-identical.

The observer/verifier is a separate process using stdlib and direct Windows APIs.
It does not import Guardian policy/broker/IPC/recovery or Hermes. Its verification
contract is fixed to the five laboratory scenarios. Portable tamper tests exercise
captured evidence, not current OS enforcement. Independent human review and a
second physical Windows host remain NOT_COVERED.

The two development startup failures (missing offline output parent) are preserved,
not counted as passing tests. The fixture setup was repaired before cold replay.
Final results and archive hashes are appended after the complete replay finishes.

## Complete cold replay at 0d45aae

| Population | Normal | Repeat | Python -O |
| --- | --- | --- | --- |
| units | 67 / True | 67 / True | 67 / True |
| v0 | 17/17; True | 17/17; True | 17/17; True |
| v02 | 41/41; True | 41/41; True | 41/41; True |
| v03 | 21/21; True | 21/21; True | 21/21; True |
| v04 | 15/15; True | 15/15; True | 15/15; True |
| v05_scripted | 5/5; True | 5/5; True | 5/5; True |
| v06_live | 5/5; True | NOT_COVERED: POLICY_CHANGE | 5/5; True |
| v07_live | 5/5; True | 5/5; True | 5/5; True |
| v07_deterministic | 5/5; True | 5/5; True | 5/5; True |
| v07_mutations | {"KILLED": 4} | {"KILLED": 4} | {"KILLED": 4} |

Machine-readable source: [V07_SUMMARY.json](V07_SUMMARY.json).
Counts are versioned populations. Repeats are not additional distinct boundaries.
The final documentation/evidence commit preserves the tested implementation bytes.

## Preserved historical live failure

v0.6 normal and optimized replay passed 5/5 scenarios and 72/72 checks.
The repeat exited 1 at POLICY_CHANGE: the model returned the complete instruction
as content (152 UTF-8 bytes), exceeding the existing 128-byte limit.
The relay rejected it with `ValueError: CONTENT` before an action tool result.
This is an unavailable live witness, not an authorization bypass or mutation kill.
No output was edited and no replacement run was used. Resource non-execution
is not inferred for that aborted case. Historical v0.6 semantic determinism
is NOT_COVERED for this campaign. The separate v0.7 campaign passed all three
modes; neither population substitutes for the other.

## Immutable public evidence

| Archive | SHA-256 |
| --- | --- |
| v07-cold-replay.zip | `8d0970d7197c668283cbbf1da5a41d429b7b33f7dc5b147d455e5bbfcebc08c8` |
| v07-development-witness.zip | `3d8e6012c078188c428ff7581102bc6d8b71aed0cbc44ccbe6419be6699491a7` |
| v07-development.zip | `f56241bd78940e741024fca3bd5922e64956960e2ecec4bc3bf1c4e21343b412` |
| v07-historical-replay.zip | `f322e536d3b833d43d5daae3e697347f67426712ebefad251c5f5e3e866b453c` |

Each archive has an adjacent member inventory. Raw local failures remain preserved;
public path-redacted derivatives record original and published hashes separately.
No historical archive was rewritten.
