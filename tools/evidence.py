"""Small byte-preserving evidence packager and independent archive inventory check."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1]
def sha(raw):return hashlib.sha256(raw).hexdigest()


def package(archive,sources):
    archive=archive.absolute()
    if archive.exists():raise ValueError('refusing to overwrite historical archive')
    archive.parent.mkdir(parents=True,exist_ok=True);members={}
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for source in sources:
            alias,location=source.split('=',1);root=Path(location).absolute()
            if not root.is_dir():raise ValueError('missing evidence directory: '+str(root))
            for p in sorted(root.rglob('*')):
                relative=p.relative_to(root)
                if not p.is_file() or any(part in ('checkout','__pycache__') for part in relative.parts):continue
                name=alias+'/'+relative.as_posix()
                if name in members:raise ValueError('duplicate archive member')
                raw=p.read_bytes();info=zipfile.ZipInfo(name,(2026,10,24,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
                z.writestr(info,raw);members[name]={'sha256':sha(raw),'bytes':len(raw)}
    report={'schema':'guardian.evidence-archive.v0','archive_sha256':sha(archive.read_bytes()),'members':members}
    archive.with_suffix('.inventory.json').write_bytes(json.dumps(report,sort_keys=True,indent=2).encode()+b'\n')
    print(json.dumps({'archive':archive.name,'sha256':report['archive_sha256'],'members':len(members),'bytes':archive.stat().st_size}))


def verify(archive):
    manifest=json.loads(archive.with_suffix('.inventory.json').read_bytes())
    errors=[]
    if sha(archive.read_bytes())!=manifest['archive_sha256']:errors.append('archive digest')
    with zipfile.ZipFile(archive) as z:
        names=z.namelist()
        if len(names)!=len(set(names)) or set(names)!=set(manifest['members']):errors.append('member inventory')
        for name,spec in manifest['members'].items():
            if name not in names:continue
            raw=z.read(name)
            if sha(raw)!=spec['sha256'] or len(raw)!=spec['bytes']:errors.append(name)
    print(json.dumps({'archive':archive.name,'members':len(manifest['members']),'errors':errors},sort_keys=True))
    return not errors


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('operation',choices=['package','verify']);p.add_argument('archive',type=Path);p.add_argument('--source',action='append',default=[]);a=p.parse_args()
    if a.operation=='package':package(a.archive,a.source)
    else:raise SystemExit(not verify(a.archive))
