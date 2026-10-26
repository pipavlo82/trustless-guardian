"""Diagnostic physical control: unexpected child termination must break the test."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.v03_campaign import Lab03,allowed,write


def run(out):
    out=out.absolute();lab=Lab03(out);worker=lab.runtime/'v03_worker.py';original=worker.read_bytes();caught=None
    try:
        positive=lab.roundtrip('positive');positive_ok=allowed(positive)
        old=b"if cfg.get('fixture_crash')==stage:os._exit(73)"
        if original.count(old)!=1:raise RuntimeError('CONTROL_NOT_APPLIED')
        changed=original.replace(old,b"if cfg.get('fixture_crash')==stage:os._exit(74)")
        worker.write_bytes(changed);before=lab.resource.read_bytes()
        try:lab.roundtrip('unexpected',server_options={'fixture_crash':'PREPARED'})
        except RuntimeError as exc:caught=str(exc)
        finally:worker.write_bytes(original)
        unchanged=lab.resource.read_bytes()==before
        observation=json.loads((out/'unexpected.observation.json').read_bytes())
        restored=lab.roundtrip('restored');exact=worker.read_bytes()==original
        result={'schema':'guardian.harness-control.v03','classification':'CONTROL_BROKEN_DETECTED' if caught=='SERVER_CONTROL_BROKEN' else 'NOT_DETECTED',
          'positive_ok':positive_ok,'restored_positive_ok':allowed(restored),'restored_byte_exact':exact,'protected_bytes_unchanged_during_crash':unchanged,
          'actual_server_exit':observation['server_exit'],'expected_fault_exit':73,'original_sha256':hashlib.sha256(original).hexdigest(),
          'mutated_sha256':hashlib.sha256(changed).hexdigest(),'security_mutation_population':False}
        result['passed']=positive_ok and allowed(restored) and exact and unchanged and observation['server_exit']==74 and caught=='SERVER_CONTROL_BROKEN'
        write(out/'report.json',result);return result
    finally:worker.write_bytes(original);lab.close()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();r=run(a.out);print(json.dumps(r));raise SystemExit(not r['passed'])
