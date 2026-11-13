"""Independent read-only IPC evidence verifier and in-memory mutation controls."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parent
SOURCE=ROOT/"reference_core"/"agent.py"
GUARDIAN=Path(__file__).resolve().parents[2]
PIN="457148f43d0cfb28b4c7c88bbf8a1d92963d77ab"
SOURCE_HASH="6bb44b71c62f54a3e1da2c11c73de5cf33766b8146c9c73f67711b9c07f0f1f6"

def require(ok,code):
    if not ok:raise ValueError(code)

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def read(name):
    return json.loads((EVIDENCE/name).read_text(encoding="utf-8"))

def verify_case(case,record):
    require(record.get("schema")=="resonance.guardian-ipc-experiment.v0","SCHEMA")
    require(record.get("guardian_head")==PIN and record.get("original_agent_sha256")==SOURCE_HASH,"SOURCE")
    require(record.get("temporary_root_deleted") is True,"TEMP_CLEANUP")
    require(record.get("no_user_python_acl_mutation") is True,"ACL_NOT_SCOPE")
    require(record.get("docker_execution") is False and record.get("guardian_grant_issued") is False and record.get("production_ready") is False,"SCOPE")
    token=record.get("agent_token")
    witness=record.get("broker_witness")
    require(type(token) is dict and type(witness) is dict,"WITNESS_TYPE")
    require(token.get("appcontainer") is True and token.get("capability_count")==0 and token.get("elevated") is False,"APPCONTAINER_TOKEN")
    require(token.get("integrity_sid")=="S-1-16-4096","LOW_INTEGRITY")
    sid=token.get("appcontainer_sid")
    require(type(sid) is str and sid.startswith("S-1-15-2-"),"SID")
    sid_sha=hashlib.sha256(sid.encode()).hexdigest()
    require(witness.get("client_identity",{}).get("appcontainer") is True and witness["client_identity"].get("capability_count")==0,"IMPERSONATION")
    require(witness["client_identity"].get("sid_sha256")==sid_sha and witness.get("expected_appcontainer_sid_sha256")==sid_sha,"SID_BINDING")
    require(witness.get("client_docker_pipe_errors")=={"linux":5,"legacy":5},"DOCKER_PIPE_ERRORS")
    require(witness.get("agent_ticks")==3,"ORIGINAL_CORE_TICKS")
    require(witness.get("guardian_grant_issued") is False and witness.get("tool_executed") is False,"NO_GRANT_NO_EXECUTION")
    require(witness.get("nonce_replay_test")=="NOT_COVERED_SINGLE_CONNECTION","REPLAY_OVERCLAIM")
    expected_tool="resonance.synthetic-hash-only.v0" if case!="bad_tool" else "shell"
    require(witness.get("client_requested_tool")==expected_tool,"TOOL_BINDING")
    if case=="normal":
        require(record.get("agent_exit")==73 and record.get("broker_exit")==0,"EXIT_POSITIVE")
        require(record.get("verdict")=="IPC_SID_AUTH_CORE_HOLD_PASS" and witness.get("verdict")=="IPC_AUTHENTICATED_TOOL_HOLD","VERDICT_POSITIVE")
        require(witness.get("nonce_binding_valid") is True,"NONCE_POSITIVE")
    elif case in ("bad_nonce","bad_tool"):
        require(record.get("agent_exit")==75 and record.get("broker_exit")==3,"EXIT_NEGATIVE")
        require(record.get("verdict")=="IPC_BAD_INTENT_DENIED" and witness.get("verdict")=="DENY_REQUEST_OR_NONCE","DENY_NEGATIVE")
        require(witness.get("nonce_binding_valid") is (case=="bad_tool"),"NONCE_CLASSIFICATION")
    else:raise ValueError("CASE_UNKNOWN")

def verify_spoof(record):
    require(record.get("schema")=="resonance.guardian-ipc-host-spoof.v0","SPOOF_SCHEMA")
    require(record.get("verdict")=="HOST_SPOOF_DENIED" and record.get("host_client_exit")==74 and record.get("broker_exit")==3,"SPOOF_VERDICT")
    require(record.get("profile_deleted") is True and record.get("production_ready") is False,"SPOOF_SCOPE")
    b=record.get("broker_witness",{})
    require(b.get("verdict")=="DENY_CLIENT_IDENTITY","SPOOF_SERVER_DENY")
    require(b.get("client_identity",{}).get("appcontainer") is False,"SPOOF_NOT_APPCONTAINER")
    require(b.get("guardian_grant_issued") is False and b.get("tool_executed") is False,"SPOOF_NO_GRANT")
    require(b.get("expected_appcontainer_sid_sha256")==record.get("expected_appcontainer_sid_sha256"),"SPOOF_EXPECTED_SID")

def verify_outage(record):
    require(record.get("schema")=="resonance.guardian-ipc-outage.v0","OUTAGE_SCHEMA")
    require(record.get("source_guardian_sha")==PIN and record.get("original_agent_sha256")==SOURCE_HASH,"OUTAGE_SOURCE")
    require(record.get("broker_started") is False and record.get("grant_issued") is False and record.get("tools_executed") is False,"OUTAGE_NO_AUTH")
    require(record.get("production_ready") is False and record.get("root_removed") is True,"OUTAGE_SCOPE")
    require(record.get("agent_exit")==86 and record.get("verdict")=="BROKER_UNAVAILABLE_TOOL_DENIED","OUTAGE_DENY")
    token=record.get("client_token",{})
    require(token.get("appcontainer") is True and token.get("capability_count")==0 and token.get("elevated") is False,"OUTAGE_TOKEN")
    require(token.get("integrity_sid")=="S-1-16-4096","OUTAGE_INTEGRITY")

def mutation_controls(cases,spoof,outage):
    base=cases["normal"]
    variants=[]
    def mutate(label,mutation):
        clone=copy.deepcopy(base)
        mutation(clone)
        variants.append((label,clone))
    mutate("agent_bogus_sid",lambda q:q["agent_token"].__setitem__("appcontainer_sid","S-1-15-2-other"))
    mutate("token_wrong_appcontainer",lambda q:q["agent_token"].__setitem__("appcontainer",False))
    mutate("token_extra_capability",lambda q:q["agent_token"].__setitem__("capability_count",1))
    mutate("token_elevated",lambda q:q["agent_token"].__setitem__("elevated",True))
    mutate("broker_sid_mismatch",lambda q:q["broker_witness"]["client_identity"].__setitem__("sid_sha256","0"*64))
    mutate("broker_grant_self_issued",lambda q:q["broker_witness"].__setitem__("guardian_grant_issued",True))
    mutate("broker_executed_false_claim",lambda q:q["broker_witness"].__setitem__("tool_executed",True))
    mutate("docker_linux_access_succeeded",lambda q:q["broker_witness"]["client_docker_pipe_errors"].__setitem__("linux",0))
    mutate("request_tool_substitution",lambda q:q["broker_witness"].__setitem__("client_requested_tool","shell"))
    mutate("nonce_wrong",lambda q:q["broker_witness"].__setitem__("nonce_binding_valid",False))
    mutate("agent_exit_mutation",lambda q:q.__setitem__("agent_exit",0))
    mutate("scope_production_claim",lambda q:q.__setitem__("production_ready",True))
    mutate("no_cleanup",lambda q:q.__setitem__("temporary_root_deleted",False))
    killed=[]
    for name,clone in variants:
        try:verify_case("normal",clone)
        except ValueError:killed.append(name)
        else:raise RuntimeError("MUTANT_SURVIVED:"+name)
    spoof_mut=copy.deepcopy(spoof)
    spoof_mut["broker_witness"]["client_identity"]["appcontainer"]=True
    try:verify_spoof(spoof_mut)
    except ValueError:killed.append("spoof_identity_mutation")
    else:raise RuntimeError("MUTANT_SURVIVED:spoof")
    outage_mut=copy.deepcopy(outage)
    outage_mut["agent_exit"]=73
    try:verify_outage(outage_mut)
    except ValueError:killed.append("outage_false_success_claim")
    else:raise RuntimeError("MUTANT_SURVIVED:outage")
    outage_mut2=copy.deepcopy(outage)
    outage_mut2["grant_issued"]=True
    try:verify_outage(outage_mut2)
    except ValueError:killed.append("outage_false_grant_claim")
    else:raise RuntimeError("MUTANT_SURVIVED:outage_grant")
    return killed

def main(out):
    global EVIDENCE
    EVIDENCE=Path(out).resolve().parent
    head=subprocess.run(["git","-C",str(GUARDIAN),"rev-parse","HEAD"],capture_output=True,text=True,check=True).stdout.strip()
    ancestor=subprocess.run(["git","-C",str(GUARDIAN),"merge-base","--is-ancestor",PIN,head],
                            capture_output=True,check=False).returncode==0
    require(ancestor and sha(SOURCE)==SOURCE_HASH,"SOURCE_DRIFT")
    cases={name:read("evidence_"+name+".json") for name in ("normal","bad_nonce","bad_tool")}
    for name,record in cases.items():verify_case(name,record)
    spoof=read("host_spoof_result.json")
    verify_spoof(spoof)
    outage=read("outage_result.json")
    verify_outage(outage)
    killed=mutation_controls(cases,spoof,outage)
    result={
      "schema":"resonance.guardian-ipc-independent-verification.v0",
      "guardian_head":PIN,"original_agent_sha256":SOURCE_HASH,
      "normal":"IPC_AUTHENTICATED_TOOL_HOLD",
      "bad_nonce":"DENIED","bad_tool":"DENIED","host_spoof":"DENIED",
      "broker_outage":"DENIED",
      "docker_pipes_inside_appcontainer":{"linux":"ACCESS_DENIED_5","legacy":"ACCESS_DENIED_5"},
      "source_mutations_executed":False,
      "in_memory_evidence_mutations_killed":len(killed),"mutations":killed,
      "client_os_identity_verified":True,
      "broker_identity_to_client":"NOT_ESTABLISHED",
      "guardian_execution_grant":"NOT_ISSUED",
      "actual_tool_execution":"NOT_PERFORMED",
      "nonce_replay":"NOT_COVERED_SINGLE_CONNECTION",
      "runtime":"ISOLATED_PYTHON_STDLIB_REAL_STATE_DECIDE_ONLY",
      "production_ready":False,
      "verdict":"LOCAL_IPC_CLIENT_SID_AUTHENTICATION_PASS_PRODUCTION_HOLD",
      "source_sha256":{n:sha(ROOT/n) for n in
                       ("broker_host.py","appcontainer_client.py","run_ipc_lab.py","host_pipe_client.py","host_spoof_lab.py","outage_lab.py")}
    }
    out=Path(out)
    if out.exists():raise RuntimeError("REPORT_EXISTS")
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"verdict":result["verdict"],"negative_tests":3,"mutants_killed":len(killed),"out":str(out)},sort_keys=True))

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--out",type=Path,required=True)
    q=p.parse_args()
    main(q.out)
