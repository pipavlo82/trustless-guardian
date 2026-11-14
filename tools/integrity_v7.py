"""Strict v7 frozen Git-tree inventory; does not waive historical v6 failure."""
import argparse,hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE="be31c67bf5a5dac41260d17fb7aabc01d7539e66"
CONTROLS={"integrity/v7/policy.json","integrity/v7/frozen.sha256.json","tools/integrity_v7.py"}
def digest(b):return hashlib.sha256(b).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def require(x,reason):
 if not x:raise ValueError(reason)
def load(path):
 raw=path.read_bytes()
 def pairs(items):
  out={}
  for k,v in items:
   require(k not in out,"DUPLICATE_MEMBER");out[k]=v
  return out
 obj=json.loads(raw,object_pairs_hook=pairs)
 require(raw==canonical(obj),"NONCANONICAL")
 return obj,raw
def verify(pin):
 policy,raw=load(ROOT/"integrity/v7/policy.json")
 require(digest(raw)==pin,"POLICY_PIN")
 require(policy["schema"]=="guardian.integrity-transition.v7" and policy["base_commit"]==BASE,"POLICY_ID")
 require(set(policy["control_files"])==CONTROLS,"CONTROLS")
 require(policy["historical_policy"]=="integrity/v6/policy.json","V6_PATH")
 require(digest((ROOT/policy["historical_policy"]).read_bytes())==policy["historical_policy_sha256"],"V6_UNCHANGED")
 require(policy["explicit_replacement"]=="research/guardian_mutual_ipc_v1/verify_evidence.py","REPLACEMENT_PATH")
 require(policy["historical_pass_commit"]=="a4000372526014e30939d07499ad038ff29aabb7","HISTORICAL_COMMIT")
 require(set(policy["permitted_additions"])==CONTROLS,"PERMITTED_ADDITIONS")
 require(set(policy["historical_manifest_hashes"])=={"integrity/v6/candidate-base.sha256.json","integrity/v6/repair-files.sha256.json"},"HISTORICAL_MANIFESTS")
 for name,d in policy["historical_manifest_hashes"].items():
  require(digest((ROOT/name).read_bytes())==d,"HISTORICAL_MANIFEST_CHANGED")
 old=subprocess.check_output(["git","show",policy["historical_pass_commit"]+":"+policy["explicit_replacement"]],cwd=ROOT)
 predecessor=subprocess.check_output(["git","show",BASE+":"+policy["explicit_replacement"]],cwd=ROOT)
 require(digest(old)==policy["previous_verifier_sha256"],"PREVIOUS_VERIFIER_HASH")
 require(digest(predecessor)==policy["predecessor_verifier_sha256"],"PREDECESSOR_VERIFIER_HASH")
 require(policy["predecessor_verifier_sha256"]==policy["replacement_sha256"],"TRANSITION_BINDING")
 require(policy["previous_verifier_sha256"]!=policy["replacement_sha256"],"NO_TRANSITION")
 require(subprocess.run(["git","merge-base","--is-ancestor",BASE,"HEAD"],cwd=ROOT).returncode==0,"ANCESTRY")
 manifest,manifest_raw=load(ROOT/"integrity/v7/frozen.sha256.json")
 require(digest(manifest_raw)==policy["frozen_sha256"],"MANIFEST_PIN")
 require(manifest["schema"]=="guardian.integrity-frozen-inventory.v7" and manifest["base_commit"]==BASE,"MANIFEST_ID")
 expected=manifest["files"]
 require(len(expected)==policy["frozen_count"]==381,"COUNT")
 require(expected[policy["explicit_replacement"]]==policy["replacement_sha256"],"REPLACEMENT_HASH")
 require(not CONTROLS.intersection(expected),"OVERLAP")
 actual={}
 for p in ROOT.rglob("*"):
  if not p.is_file() or ".git" in p.parts or "__pycache__" in p.parts:continue
  name=p.relative_to(ROOT).as_posix()
  if name.startswith(".git/") or name.endswith(".pyc"):continue
  actual[name]=digest(p.read_bytes())
 missing=sorted((set(expected)|CONTROLS)-set(actual))
 extra=sorted(set(actual)-set(expected)-CONTROLS)
 changed=sorted(k for k in set(expected)&set(actual) if expected[k]!=actual[k])
 return dict(passed=not(missing or extra or changed),base=BASE,expected=len(expected),missing=missing,extra=extra,changed=changed,policy_pin=pin,historical_v6_preserved=True)
if __name__=="__main__":
 a=argparse.ArgumentParser();a.add_argument("--policy-sha256",required=True);args=a.parse_args()
 try:result=verify(args.policy_sha256)
 except Exception as e:result={"passed":False,"error":str(e)}
 print(json.dumps(result,sort_keys=True))
 raise SystemExit(0 if result["passed"] else 1)
