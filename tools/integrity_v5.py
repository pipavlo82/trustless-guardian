"""Strict additive PR7 preservation. v1-v4 manifests and all 354 old files are frozen."""
import argparse
import json
from pathlib import Path
import subprocess
from integrity_v2 import ROOT, IntegrityError, actual_inventory, load_digest_map, sha, strict_json

BASE = "2a40075a7f217e9c385cdfaf27c0267fa788d574"
CONTROLS = {'integrity/v5/policy.json','integrity/v5/pr7-base.sha256.json','integrity/v5/additions.sha256.json'}


def verify(pin):
    raw=(ROOT/'integrity/v5/policy.json').read_bytes()
    if sha(raw)!=pin:raise IntegrityError('POLICY_PIN')
    p=strict_json(raw)
    if type(p) is not dict or set(p)!={'schema','base_commit','frozen','additions'} or p['schema']!='guardian.additive-integrity.v5' or p['base_commit']!=BASE:raise IntegrityError('POLICY_SHAPE')
    if subprocess.run(['git','merge-base','--is-ancestor',BASE,'HEAD'],cwd=ROOT,capture_output=True).returncode:raise IntegrityError('ANCESTRY')
    maps=[]
    for section,path in [('frozen','integrity/v5/pr7-base.sha256.json'),('additions','integrity/v5/additions.sha256.json')]:
        d=p[section]
        if type(d) is not dict or set(d)!={'manifest','sha256','count'} or d['manifest']!=path or type(d['count']) is not int:raise IntegrityError('MANIFEST_SHAPE')
        maps.append(load_digest_map(ROOT/path,d['sha256'],d['count']))
    frozen, additions=maps
    if len(frozen)!=354 or set(frozen)&set(additions) or (set(frozen)|set(additions))&CONTROLS:raise IntegrityError('DISJOINT_INVENTORY')
    expected={**frozen,**additions};actual=actual_inventory()
    missing=sorted((set(expected)|CONTROLS)-set(actual))
    changed=sorted(k for k in expected.keys()&actual.keys() if expected[k]!=actual[k])
    extra=sorted(set(actual)-set(expected)-CONTROLS)
    return {'schema':'guardian.additive-integrity-result.v5','base':BASE,'frozen':len(frozen),'additions':len(additions),'actual':len(actual),
            'missing':missing,'changed':changed,'extra':extra,'passed':not(missing or changed or extra),'policy_sha256':pin}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--policy-sha256',required=True);a=p.parse_args()
    try:r=verify(a.policy_sha256)
    except (OSError,ValueError,IntegrityError) as e:r={'passed':False,'error':str(e)}
    print(json.dumps(r,sort_keys=True,separators=(',',':')))
    raise SystemExit(0 if r['passed'] else 1)
