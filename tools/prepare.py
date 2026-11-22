"""Fetch only the source-pinned official test runtime; no packages are installed."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
lock=json.loads((ROOT/'runtime-lock.json').read_bytes())
target=ROOT/'build/runtime/python-3.12.10-embed-amd64.zip'
target.parent.mkdir(parents=True,exist_ok=True)
if not target.exists():
    data=urllib.request.urlopen(lock['url'],timeout=60).read()
    if hashlib.sha256(data).hexdigest()!=lock['sha256']:raise SystemExit('runtime SHA-256 mismatch')
    target.write_bytes(data)
if hashlib.sha256(target.read_bytes()).hexdigest()!=lock['sha256']:raise SystemExit('cached runtime SHA-256 mismatch')
print('PINNED_RUNTIME_VERIFIED '+lock['sha256'])
