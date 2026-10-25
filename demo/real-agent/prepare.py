"""Copy a pinned installed Hermes runtime into a NEW disposable directory.

No profile, credential, environment file, user memory, or conversation is copied.
Never modifies the installed runtime. Third-party runtime is not published.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

PIN = 'f7c79efbac19ae18e8dee7c79a4e4c0935299b5f'


def prepare(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if not destination.name.startswith('guardian-lab-'):
        raise ValueError('DISPOSABLE_RUNTIME_NAME_MUST_START_WITH_guardian-lab-')
    head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if head != PIN or subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain']):
        raise ValueError('HERMES_SOURCE_PIN_OR_DIRTY')
    destination.mkdir(parents=True, exist_ok=False)
    cfg = dict(line.split(' = ', 1) for line in (source/'venv/pyvenv.cfg').read_text().splitlines() if ' = ' in line)
    base = Path(cfg['home'])
    # The base distribution has no user credentials; allow only runtime files.
    py = destination/'python'; py.mkdir()
    for file in base.iterdir():
        if file.is_file() and (file.suffix.lower() in {'.exe', '.dll'} or file.name.upper().startswith(('LICENSE','COPYING'))):
            shutil.copyfile(file, py/file.name)
    for name in ('Lib', 'DLLs'):
        if (base/name).exists():
            shutil.copytree(base/name, py/name, ignore=shutil.ignore_patterns('__pycache__', 'site-packages', 'test', 'tests'))
    src = destination/'hermes'; src.mkdir()
    # Only tracked program source/config templates, not private runtime state.
    files = subprocess.check_output(['git', '-C', str(source), 'ls-files', '-z']).decode().split('\0')
    for name in files:
        if not name or name.startswith(('tests/', 'docs/', '.github/', 'website/', 'benchmarks/')):
            continue
        file = source/name
        if (file.suffix.lower() not in {'.py', '.json', '.yaml', '.yml', '.txt', '.md', '.jinja', '.j2'} and not file.name.upper().startswith(('LICENSE','COPYING'))) or not file.is_file():
            continue
        if name.startswith('.') or name.endswith('.env'):
            continue
        target = src/name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(file, target)
    # Installed dependency code only. No executable .pth or editable-install links.
    site = source/'venv/Lib/site-packages'; target = py/'Lib/site-packages'; target.mkdir()
    for file in site.iterdir():
        if file.name.startswith(('__pycache__', '__editable__', 'pip', 'setuptools')) or file.suffix == '.pth':
            continue
        if file.is_dir():
            shutil.copytree(file, target/file.name, ignore=shutil.ignore_patterns('__pycache__', 'tests', 'test'))
        elif file.suffix.lower() in {'.py', '.pyd', '.dll'}:
            shutil.copyfile(file, target/file.name)
    inventory = {p.relative_to(destination).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in destination.rglob('*') if p.is_file()}
    report = {'schema': 'guardian.hermes-runtime.v06', 'hermes_commit': head, 'files': inventory,
              'profile_copied': False, 'credentials_copied': False}
    (destination/'runtime-inventory.json').write_bytes(json.dumps(report, sort_keys=True, indent=2).encode()+b'\n')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--source', type=Path, required=True); p.add_argument('--out', type=Path, required=True)
    a = p.parse_args(); r = prepare(a.source, a.out); print(json.dumps({'files': len(r['files']), 'hermes_commit': r['hermes_commit']}))
