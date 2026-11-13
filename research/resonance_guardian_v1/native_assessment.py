"""Portable reporting wrapper for genuine (not mocked) Windows AppContainer IPC.

On systems where physical controls cannot run, reports NOT_COVERED, never PASS.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
EXPECTED={"normal":"IPC_SID_AUTH_CORE_HOLD_PASS",
          "bad_nonce":"IPC_BAD_INTENT_DENIED",
          "bad_tool":"IPC_BAD_INTENT_DENIED"}

def process(args,timeout=100):
    return subprocess.run([sys.executable,"-B",*map(str,args)],cwd=str(ROOT),
        capture_output=True,text=True,timeout=timeout,check=False)

def inspect(path,key,expected):
    data=json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get(key)!=expected:
        raise RuntimeError("NOT_MATCHED_"+str(key)+":"+str(data.get(key)))
    return data

def run(output):
    output=Path(output).resolve()
    if output.exists(): raise RuntimeError("OUTPUT_ALREADY_EXISTS")
    output.mkdir(parents=True)
    report={
      "schema":"resonance.guardian-windows-appcontainer-ipc-assessment.v1",
      "scope":"NATIVE_WINDOWS_REAL_APPCONTAINER_NOT_SIMULATED",
      "windows":os.name=="nt",
      "core_snapshot":"ORIGINAL_UNMODIFIED_AGENT_STATE_DECIDE",
      "production_ready":False,
      "guardian_execution_grant":"NOT_ISSUED",
      "tool_executed":False,
      "broker_mutual_auth":"NOT_ESTABLISHED",
      "nonce_replay":"NOT_COVERED_SINGLE_CONNECTION",
      "status":"NOT_COVERED",
      "case_results":{},
      "verifier":{},
      "errors":[],
    }
    try:
        if os.name!="nt":
            report["errors"].append("NOT_WINDOWS")
            return report
        for name, expected in EXPECTED.items():
            path=output/("evidence_"+name+".json")
            p=process([ROOT/"run_ipc_lab.py","--out",path,"--case",name])
            record=inspect(path,"verdict",expected)
            if p.returncode!=0:raise RuntimeError("AGENT_EXIT_"+name+":"+str(p.returncode))
            report["case_results"][name]=record["verdict"]
        path=output/"host_spoof_result.json"
        p=process([ROOT/"host_spoof_lab.py","--out",path])
        inspect(path,"verdict","HOST_SPOOF_DENIED")
        if p.returncode:raise RuntimeError("SPOOF_EXIT")
        report["case_results"]["host_spoof"]="DENIED_CLIENT_IDENTITY"
        path=output/"outage_result.json"
        p=process([ROOT/"outage_lab.py","--out",path])
        inspect(path,"verdict","BROKER_UNAVAILABLE_TOOL_DENIED")
        if p.returncode:raise RuntimeError("OUTAGE_EXIT")
        report["case_results"]["broker_outage"]="DENIED"
        for mode,optimized in (("normal",False),("repeat",False),("optimized",True)):
            output_path=output/("verification_"+mode+".json")
            cmd=[sys.executable]+(["-O"] if optimized else [])+["-B",
                str(ROOT/"verify_evidence.py"),"--out",str(output_path)]
            p=subprocess.run(cmd,capture_output=True,text=True,timeout=30,cwd=str(ROOT))
            if p.returncode:raise RuntimeError("VERIFIER_"+mode+":"+p.stderr[-450:])
            result=inspect(output_path,"verdict","LOCAL_IPC_CLIENT_SID_AUTHENTICATION_PASS_PRODUCTION_HOLD")
            if result["in_memory_evidence_mutations_killed"]!=16:raise RuntimeError("MUTATION_NOT_KILLED")
            report["verifier"][mode]={"status":"PASS","mutants_killed":16}
        report["status"]="VERIFIED_LOCAL_NATIVE_IPC"
    except (OSError,ValueError,KeyError,RuntimeError,subprocess.TimeoutExpired) as exc:
        report["errors"].append(type(exc).__name__+":"+str(exc)[:440])
    finally:
        (output/"assessment.json").write_text(
            json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"status":report["status"],"case_results":report["case_results"],
               "verifier":report["verifier"],"errors":report["errors"]},sort_keys=True))
    return report

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--strict",action="store_true")
    opts=parser.parse_args()
    r=run(opts.out)
    raise SystemExit(0 if r["status"]=="VERIFIED_LOCAL_NATIVE_IPC" or not opts.strict else 2)
