# Frozen Resonance Core V2.3 (research)

`core_v2_3.py` is byte-identical to the evaluated Windows source:
`10790b3fb770496e8213986a320b825fd90dbc9990c96df81fa809fdd5ff257f`.

`core_v2_2.py`, `core_v2_1.py`, `core_v2.py` and `common.py` provide read-only baselines. `support_v23.py` is a portable compatibility module; it is **not** the original frozen support file and must not be cited as that file. The `__init__.py` loader exposes the unchanged Core V2.3 with local sibling imports.

Usage, from repository root (Python 3.12 + PyNaCl):

```powershell
python -B -m research.resonance_core_v23.SMOKE_REPLAY
```

This is a deterministic advisory heuristic, not an autonomous production authorization system. Matched-source scientific experiments were local and involved controlled failures only. Core output is a proposal; Guardian independently authorizes any execution.
