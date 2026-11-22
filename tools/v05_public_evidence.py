"""Publish path-redacted derivatives; never rewrite original raw observations.

Only explicit experiment output directories are read. Executable payloads and
disposable checkout copies are excluded. Original and derivative hashes remain
distinct. Originals stay in ignored local output directories.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def export(destination, sources):
    destination.mkdir(parents=True, exist_ok=False); inventory = {}
    for argument in sources:
        alias, location = argument.split('=', 1); root = Path(location).resolve()
        for path in sorted(root.rglob('*')):
            relative = path.relative_to(root)
            if not path.is_file() or any(x in ('checkout', '__pycache__') for x in relative.parts): continue
            raw = path.read_bytes()
            try: text = raw.decode('utf-8')
            except UnicodeDecodeError: continue  # Never include binary runtimes.
            # Normalize only identifying host paths. Synthetic SIDs, native errors,
            # measurements, content bytes, source/evidence hashes stay unchanged.
            text = re.sub(r'[A-Za-z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/)[^"\r\n]*?(?=(?:"|\r|\n|$))', '<USER_LOCAL_PATH>', text)
            for prefix in ('D:/PAVLO HQ/Workspaces/', 'D:\\PAVLO HQ\\Workspaces\\', 'D:\\\\PAVLO HQ\\\\Workspaces\\\\'):
                text = text.replace(prefix, '<WORKSPACES>/')
            published = text.encode('utf-8')
            name = alias+'/'+relative.as_posix(); target = destination/name
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(published)
            inventory[name] = {'original_sha256': hashlib.sha256(raw).hexdigest(),
                               'published_sha256': hashlib.sha256(published).hexdigest(),
                               'path_redacted': raw != published}
    (destination/'redaction-manifest.json').write_bytes(json.dumps({
        'schema': 'guardian.public-evidence.v05', 'originals_retained_locally': True,
        'not_byte_identical_to_original_when_redacted': True, 'files': inventory}, sort_keys=True, indent=2).encode()+b'\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--out', type=Path, required=True)
    p.add_argument('--source', action='append', required=True); a = p.parse_args(); export(a.out, a.source)
