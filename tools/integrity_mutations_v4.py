"""Physical file mutations for PR #7's exact layered integrity policy (restored every time)."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
SPECS=(
 ("modified-frozen-readme","append","README.md"),
 ("missing-frozen-readme","remove","README.md"),
 ("modified-pr6-durable","append","research/replay_challenge_v1/durable.py"),
 ("tampered-v3-policy","append","integrity/v3/policy.json"),
 ("tampered-v3-authorized","append","integrity/v3/replay-challenge-files.sha256.json"),
 ("tampered-pr6-frozen","append","integrity/v4/pr6-base.sha256.json"),
 ("missing-pr6-frozen","remove","integrity/v4/pr6-base.sha256.json"),
 ("tampered-v4-additions","append","integrity/v4/resonance-ipc-files.sha256.json"),
 ("modified-original-core","append","research/resonance_guardian_v1/reference_core/agent.py"),
 ("modified-ipc-broker","append","research/resonance_guardian_v1/broker_host.py"),
 ("missing-ipc-runner","remove","research/resonance_guardian_v1/native_assessment.py"),
 ("modified-ci-workflow","append",".github/workflows/replay-challenge-v1.yml"),
 ("tampered-v4-policy","append","integrity/v4/policy.json"),
 ("missing-bootstrap","remove",".github/workflows/resonance-guardian-v1.yml"),
 ("unexpected-file","create","INTEGRITY_V4_UNAUTHORIZED.tmp"),
)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def check(pin):
    r=subprocess.run([sys.executable,"-B","tools/integrity_v4.py","--policy-sha256",pin],
        cwd=ROOT,capture_output=True)
    return {"exit_code":r.returncode,"stdout_sha256":sha(r.stdout),"stderr_sha256":sha(r.stderr)}

def run(pin,out):
    rows=[]
    for name,action,path in SPECS:
        target=ROOT/path
        before=target.read_bytes() if target.is_file() else None
        baseline=check(pin)
        applied=False
        try:
            if action=="append" and before is not None:
                target.write_bytes(before+b"INTEGRITY_V4_MUTATION")
                applied=True
            elif action=="remove" and before is not None:
                target.unlink()
                applied=True
            elif action=="create" and not target.exists():
                target.write_bytes(b"unauthorized\n")
                applied=True
            mutated=check(pin) if applied else None
        finally:
            if before is not None:
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(before)
            elif target.exists():
                target.unlink()
        restored_bytes=(target.read_bytes()==before) if before is not None else (not target.exists())
        restored=check(pin)
        if baseline["exit_code"]!=0 or restored["exit_code"]!=0 or not restored_bytes:
            status="CONTROL_BROKEN"
        elif not applied:status="NOT_APPLIED"
        elif mutated is None or mutated["exit_code"] not in (0,1,2):status="CRASHED"
        elif mutated["exit_code"]==0:status="SURVIVED"
        else:status="KILLED"
        rows.append({"mutation":name,"action":action,"path":path,"status":status,
                     "applied":applied,"restored":restored_bytes,
                     "original_sha256":sha(before) if before is not None else None,
                     "baseline":baseline,"mutated":mutated,"restored_control":restored})
    statuses=("KILLED","SURVIVED","NOT_APPLIED","CRASHED","CONTROL_BROKEN")
    counts={s:sum(row["status"]==s for row in rows) for s in statuses}
    okay=counts=={"KILLED":len(rows),"SURVIVED":0,"NOT_APPLIED":0,"CRASHED":0,"CONTROL_BROKEN":0}
    result={"schema":"guardian.integrity-mutations.v4","population":len(rows),"counts":counts,
            "results":rows,"verdict":"PASS" if okay else "HOLD"}
    out=Path(out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="ascii")
    print(json.dumps({"counts":counts,"verdict":result["verdict"]},sort_keys=True))
    return okay

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--policy-sha256",required=True)
    p.add_argument("--out",required=True,type=Path)
    v=p.parse_args()
    raise SystemExit(0 if run(v.policy_sha256,v.out) else 1)
