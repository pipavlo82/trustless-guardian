"""v0.6 public derivatives: redact host paths and base-user SID, retain originals."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from v05_public_evidence import export


def publish(destination, sources):
    export(destination, sources)
    manifest = json.loads((destination/'redaction-manifest.json').read_bytes())
    for name, record in manifest['files'].items():
        path=destination/name; raw=path.read_bytes()
        public=re.sub(rb'S-1-5-21-\d+-\d+-\d+-\d+', b'<HOST_USER_SID>', raw)
        if public!=raw:
            path.write_bytes(public);record['host_sid_redacted']=True
            record['published_sha256']=hashlib.sha256(public).hexdigest()
    manifest['schema']='guardian.public-evidence.v06'
    (destination/'redaction-manifest.json').write_bytes(json.dumps(manifest,sort_keys=True,indent=2).encode()+b'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--source',action='append',required=True);a=p.parse_args();publish(a.out,a.source)
