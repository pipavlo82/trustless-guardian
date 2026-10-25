"""Exact tracked/unignored file inventory. Regeneration is an explicit author action."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
MANIFEST='artifacts.sha256.json'


def inventory():
    files=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=ROOT).decode().split('\0')
    return {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(set(files)) if name and name!=MANIFEST and (ROOT/name).is_file()}


def verify(expected,actual):
    return {'missing':sorted(set(expected)-set(actual)),'unlisted':sorted(set(actual)-set(expected)),
      'changed':sorted(k for k in set(expected)&set(actual) if expected[k]!=actual[k])}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');a=p.parse_args();actual=inventory()
    if a.write:
        (ROOT/MANIFEST).write_bytes(json.dumps(actual,indent=2,sort_keys=True).encode()+b'\n')
        print('WROTE',len(actual));raise SystemExit(0)
    result=verify(json.loads((ROOT/MANIFEST).read_bytes()),actual)
    print(json.dumps({'files':len(actual),**result},sort_keys=True));raise SystemExit(any(result.values()))
