"""Explicit additive lab inventory. Never changes or bypasses historical v8."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BASE='299487d7d7884b2cb2adc7df86b6485ee18daba7'
PREFIX='research/scoped_execution_lab_v1/'
def sha(b):return hashlib.sha256(b).hexdigest()
def verify(pin):
    manifest=ROOT/PREFIX/'SOURCE_SHA256.json';raw=manifest.read_bytes()
    if sha(raw)!=pin:raise ValueError('LAB_MANIFEST_PIN')
    added=json.loads(raw);errors=[]
    tree=subprocess.check_output(['git','ls-tree','-rz',BASE],cwd=ROOT).split(b'\0');expected={}
    for row in filter(None,tree):
        meta,name=row.split(b'\t');name=name.decode();oid=meta.split()[2].decode()
        expected[name]=sha(subprocess.check_output(['git','cat-file','blob',oid],cwd=ROOT))
    if set(expected)&set(added):raise ValueError('HISTORICAL_REPLACEMENT')
    if any(not p.startswith(PREFIX) for p in added):raise ValueError('EXTENSION_SCOPE')
    combined={**expected,**added}
    for name,digest in combined.items():
        p=ROOT/name
        if not p.is_file() or sha(p.read_bytes())!=digest:errors.append(name)
    actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file() and not any(x in ('.git','build','__pycache__') for x in p.relative_to(ROOT).parts)}
    extra=sorted(actual-set(combined)-{PREFIX+'SOURCE_SHA256.json'})
    return {'base':BASE,'preserved':len(expected)-len([x for x in errors if x in expected]),'baseline_count':len(expected),'new_count':len(added),'changed_or_missing':errors,'extra':extra,'passed':not errors and not extra,'historical_v8_on_extended_tree':'EXPECTED_REFUSAL_UNCHANGED'}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--pin',required=True);a=p.parse_args()
    try:r=verify(a.pin)
    except Exception as e:r={'passed':False,'error':str(e)}
    print(json.dumps(r,sort_keys=True));raise SystemExit(0 if r['passed'] else 1)
