"""Preserve the starting core and historical evidence without Git-depth assumptions."""
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
ALLOWED={'.github/workflows/guardian.yml','README.md','THIRD_PARTY_NOTICES.md'}


def verify():
    original=json.loads((ROOT/'research/V06_BASELINE_INVENTORY.json').read_bytes())
    missing=[];changed=[];allowed=[]
    for name,expected in original.items():
        path=ROOT/name
        if not path.is_file():missing.append(name)
        elif hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
            (allowed if name in ALLOWED else changed).append(name)
    return {'starting_head':'1a7212e9cd8a0a8b097a095b25a8cd3f0b35e8f8','files':len(original),
            'missing':missing,'unexpected_changes':changed,'declared_changes':allowed,
            'passed':not missing and not changed}


if __name__=='__main__':
    r=verify();print(json.dumps(r,sort_keys=True));raise SystemExit(not r['passed'])
