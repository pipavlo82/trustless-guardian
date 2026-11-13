"""Read-only local challenge: normal host process is rejected by SID-bound broker."""
import hashlib,json,os,subprocess,sys,time,uuid,secrets
from pathlib import Path
HERE=Path(__file__).resolve().parent
G=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(G))
from guardian.windows import Container
def run(out):
    out=Path(out).resolve()
    if out.exists() or not out.parent.is_dir(): raise RuntimeError("EVIDENCE_PATH")
    name="guardian-resonance-"+secrets.token_hex(12)
    c=Container("resonance-ipc-spoof-"+uuid.uuid4().hex[:12])
    ready=out.parent/("spoof-ready-"+secrets.token_hex(6)+".txt")
    broker_out=out.parent/("spoof-broker-"+secrets.token_hex(6)+".json")
    broker=None
    report={"schema":"resonance.guardian-ipc-host-spoof.v0","expected_appcontainer_sid_sha256":hashlib.sha256(c.principal.encode()).hexdigest(),
            "production_ready":False,"verdict":"INCONCLUSIVE"}
    try:
        broker=subprocess.Popen([sys.executable,"-B",str(HERE/"broker_host.py"),"--name",name,
                "--app-sid",c.principal,"--ready",str(ready),"--out",str(broker_out)],
                cwd=str(HERE),text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        for _ in range(100):
            if ready.exists() or broker.poll() is not None: break
            time.sleep(0.1)
        if not ready.exists():raise RuntimeError("BROKER_START_FAILED")
        client=subprocess.run([sys.executable,"-B",str(HERE/"host_pipe_client.py"),name],
             capture_output=True,text=True,timeout=10,cwd=str(HERE))
        report["host_client_exit"]=client.returncode
        report["host_client_response"]=client.stdout.strip()[:350]
        broker_stdout,err=broker.communicate(timeout=6)
        report["broker_exit"]=broker.returncode
        report["broker_witness"]=json.loads(broker_out.read_text(encoding="utf-8"))
        report["verdict"]="HOST_SPOOF_DENIED" if (
            client.returncode==74 and broker.returncode==3 and
            report["broker_witness"]["verdict"]=="DENY_CLIENT_IDENTITY" and
            report["broker_witness"]["client_identity"]["appcontainer"] is False and
            report["broker_witness"]["guardian_grant_issued"] is False
        ) else "HOST_SPOOF_INCONCLUSIVE"
    except Exception as e:
        report["verdict"]="CONTROL_BROKEN"
        report["error"]=str(e)[:300]
    finally:
        if broker is not None and broker.poll() is None:
            broker.kill();broker.communicate(timeout=3)
        c.close()
        report["profile_deleted"]=True
        target=out
        if target.exists():raise RuntimeError("RESULT_EXISTS")
        target.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({"verdict":report["verdict"],"host_exit":report.get("host_client_exit"),
                          "broker_exit":report.get("broker_exit")}))

if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("--out",required=True,type=Path)
    args=parser.parse_args()
    run(args.out)
