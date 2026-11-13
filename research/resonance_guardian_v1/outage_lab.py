"""Physical fail-closed test: zero-capability original core without Guardian IPC broker."""
import hashlib,json,os,secrets,shutil,sys,tempfile,uuid
from pathlib import Path
from run_ipc_lab import GUARDIAN,PIN,SOURCE_SHA,check_sources,package_runtime
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(GUARDIAN))
from guardian.windows import Container,acl,low_label

def run(out):
    out=Path(out).resolve()
    if out.exists() or not out.parent.is_dir(): raise RuntimeError("EVIDENCE_PATH")
    check_sources()
    root=Path(tempfile.mkdtemp(prefix="guardian-lab-resonance-outage-",dir=os.environ["TEMP"]))
    c=None
    report={"schema":"resonance.guardian-ipc-outage.v0",
            "source_guardian_sha":PIN,"original_agent_sha256":SOURCE_SHA,
            "broker_started":False,"grant_issued":False,"tools_executed":False,
            "production_ready":False,"verdict":"INCONCLUSIVE"}
    try:
        rt=package_runtime(root)
        c=Container("resonance-ipc-outage-"+uuid.uuid4().hex[:12])
        for p in [root,rt,*rt.rglob("*")]:
            acl(root,p,c.principal,writable=False)
        low_label(root,root)
        unused_name="guardian-resonance-"+secrets.token_hex(12)
        o=c.launch([str(rt/"python.exe"),"-I","-B",str(rt/"appcontainer_client.py"),unused_name,"normal"],
                   root,timeout=20)
        report["agent_exit"]=o["exit_code"]
        t=o["token"]
        report["client_token"]={k:t.get(k) for k in ("appcontainer","capability_count","elevated","integrity_sid")}
        if o["exit_code"]==86 and t.get("appcontainer") is True and t.get("capability_count")==0 and t.get("elevated") is False:
            report["verdict"]="BROKER_UNAVAILABLE_TOOL_DENIED"
        else:
            report["verdict"]="BROKER_OUTAGE_INCONCLUSIVE"
    except Exception as e:
        report["verdict"]="CONTROL_BROKEN"
        report["error"]=str(e)[:350]
    finally:
        if c is not None:c.close()
        shutil.rmtree(root,ignore_errors=True)
        report["root_removed"]=not root.exists()
        dest=out
        if dest.exists():raise RuntimeError("OUTAGE_REPORT_EXISTS")
        dest.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({"verdict":report["verdict"],"agent_exit":report.get("agent_exit"),"root_removed":report["root_removed"]},sort_keys=True))
if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("--out",required=True,type=Path)
    args=parser.parse_args()
    run(args.out)
