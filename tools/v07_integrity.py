"""Immutable v0-v0.6 implementation/evidence baseline; only entrypoint docs/CI change."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {'README.md', '.github/workflows/guardian.yml', 'docs/SECURITY_BOUNDARIES.md'}


def verify():
    original = json.loads((ROOT/'research/V07_BASELINE_INVENTORY.json').read_bytes())
    changed = []; missing = []; declared = []
    for name, expected in original.items():
        path = ROOT/name
        if not path.is_file(): missing.append(name)
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            (declared if name in ALLOWED else changed).append(name)
    return {'starting_sha': 'b72f7b920d362d866ed0680d73b8f12a53ff37dc',
            'files': len(original), 'unexpected_changes': changed, 'missing': missing,
            'declared_changes': declared, 'passed': not changed and not missing}


if __name__ == '__main__':
    value = verify(); print(json.dumps(value, sort_keys=True)); raise SystemExit(not value['passed'])
