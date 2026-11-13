"""Disposable original-core AppContainer and separate SID-authenticated Guardian IPC broker.

No Docker execution, no live Codex, no secrets or external network.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile

HERE=Path(__file__).resolve().parent
GUARDIAN=Path(__file__).resolve().parents[2]
SOURCE=HERE/"reference_core"/"agent.py"
PIN="457148f43d0cfb28b4c7c88bbf8a1d92963d77ab"
SOURCE_SHA="6bb44b71c62f54a3e1da2c11c73de5cf33766b8146c9c73f67711b9c07f0f1f6"

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def check_sources():
    head=subprocess.run(["git","-C",str(GUARDIAN),"rev-parse","HEAD"],check=True,capture_output=True,text=True,timeout=10).stdout.strip()
    ancestor=subprocess.run(["git","-C",str(GUARDIAN),"merge-base","--is-ancestor",PIN,head],
                            capture_output=True,check=False).returncode==0
    if not ancestor or sha(SOURCE)!=SOURCE_SHA:
        raise RuntimeError("SOURCE_REVISION_MISMATCH")
    changed=subprocess.run(["git","-C",str(GUARDIAN),"status","--porcelain","--untracked-files=no"],check=True,capture_output=True,text=True,timeout=10).stdout.strip()
    if changed:raise RuntimeError("GUARDIAN_TRACKED_DIRTY")

def package_runtime(root):
    base=Path(sys.executable).parent
    rt=root/"runtime";rt.mkdir()
    for n in ["python.exe","python312.dll","python3.dll","vcruntime140.dll","vcruntime140_1.dll"]:
        shutil.copy2(base/n,rt/n)
    with zipfile.ZipFile(rt/"python312.zip","w",compression=zipfile.ZIP_DEFLATED) as z:
        for p in (base/"Lib").rglob("*.py"):
            if "site-packages" not in p.parts and "__pycache__" not in p.parts:
                z.write(p,p.relative_to(base/"Lib").as_posix())
    shutil.copytree(base/"DLLs",rt/"DLLs",ignore=shutil.ignore_patterns("*.pyc","__pycache__"))
    shutil.copy2(SOURCE,rt/"agent.py")
    shutil.copy2(HERE/"appcontainer_client.py",rt/"appcontainer_client.py")
    (rt/"psutil.py").write_text(
        "def __getattr__(name):\n raise RuntimeError('HOST_SENSORS_DISABLED')\n",encoding="ascii")
    (rt/"python312._pth").write_text("python312.zip\nDLLs\n.\n",encoding="ascii")
    return rt

def run(out,case="normal"):
    if case not in ("normal","bad_nonce","bad_tool"):
        raise ValueError("TEST_CASE")
    out=Path(out).resolve()
    if out.exists():raise RuntimeError("OUTPUT_EXISTS")
    if not out.parent.is_dir():raise RuntimeError("OUTPUT_PARENT_MISSING")
    check_sources()
    sys.path.insert(0,str(GUARDIAN))
    from guardian.windows import Container,acl,low_label
    root=Path(tempfile.mkdtemp(prefix="guardian-lab-resonance-ipc-",dir=os.environ["TEMP"]))
    c=None;broker=None
    report={"schema":"resonance.guardian-ipc-experiment.v0","guardian_head":PIN,
            "original_agent_sha256":SOURCE_SHA,"production_ready":False,
            "guardian_grant_issued":False,"docker_execution":False,"verdict":"INCONCLUSIVE"}
    try:
        rt=package_runtime(root)
        c=Container("resonance-ipc-"+uuid.uuid4().hex[:12])
        for p in [root,rt,*rt.rglob("*")]:
            acl(root,p,c.principal,writable=False)
        low_label(root,root)
        pipe_name="guardian-resonance-"+secrets.token_hex(12)
        ready=out.parent/("broker_ready_"+secrets.token_hex(6)+".txt")
        broker_out=out.parent/("broker_evidence_"+secrets.token_hex(6)+".json")
        cmd=[sys.executable,"-B",str(HERE/"broker_host.py"),"--name",pipe_name,
             "--app-sid",c.principal,"--ready",str(ready),"--out",str(broker_out)]
        broker=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                                cwd=str(HERE),creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        for _ in range(100):
            if ready.exists():break
            if broker.poll() is not None:break
            time.sleep(0.1)
        if not ready.exists():
            output,errors=broker.communicate(timeout=2)
            report.update({"verdict":"BROKER_START_FAILED","broker_exit":broker.returncode,
                           "error_tail":errors[-500:]})
            raise RuntimeError("BROKER_NOT_READY")
        observed=c.launch([str(rt/"python.exe"),"-I","-B",str(rt/"appcontainer_client.py"),pipe_name,case],root,timeout=25)
        report["agent_exit"]=observed["exit_code"]
        report["agent_token"]={k:observed["token"].get(k) for k in
                               ("appcontainer","appcontainer_sid","capability_count","integrity_sid","elevated")}
        output,errors=broker.communicate(timeout=8)
        report["broker_exit"]=broker.returncode
        report["broker_stdout"]=output[-500:]
        report["broker_stderr_tail"]=errors[-400:]
        if broker_out.is_file():
            data=json.loads(broker_out.read_text(encoding="utf-8"))
            report["broker_witness"]=data
        else:
            report["broker_witness"]={"verdict":"MISSING"}
        identity_ok=(
            report["agent_token"]["appcontainer"] is True
            and report["agent_token"]["capability_count"]==0
            and report["agent_token"]["appcontainer_sid"]==c.principal
            and report["broker_witness"]["client_identity"]["sid_sha256"]==
                hashlib.sha256(c.principal.encode()).hexdigest())
        if case=="normal":
            report["verdict"]="IPC_SID_AUTH_CORE_HOLD_PASS" if (
                identity_ok and report["agent_exit"]==73 and report["broker_exit"]==0
                and report["broker_witness"]["verdict"]=="IPC_AUTHENTICATED_TOOL_HOLD"
            ) else "IPC_INCONCLUSIVE"
        else:
            report["verdict"]="IPC_BAD_INTENT_DENIED" if (
                identity_ok and report["agent_exit"]==75 and report["broker_exit"]==3
                and report["broker_witness"]["verdict"]=="DENY_REQUEST_OR_NONCE"
            ) else "IPC_NEGATIVE_INCONCLUSIVE"
        report["case"]=case
        return report
    except Exception as e:
        report["error_type"]=type(e).__name__
        report["error"]=str(e)[:350]
        if report["verdict"]=="INCONCLUSIVE":report["verdict"]="CONTROL_BROKEN"
        return report
    finally:
        if broker is not None and broker.poll() is None:
            broker.kill()
            broker.communicate(timeout=3)
        if c is not None:c.close()
        shutil.rmtree(root,ignore_errors=True)
        report["temporary_root_deleted"]=not root.exists()
        report["no_user_python_acl_mutation"]=True
        out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"verdict":report["verdict"],"agent_exit":report.get("agent_exit"),
                          "broker_exit":report.get("broker_exit"),"out":str(out)}),flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--case",choices=("normal","bad_nonce","bad_tool"),default="normal")
    a=p.parse_args()
    r=run(a.out,a.case)
    raise SystemExit(0 if r["verdict"] in ("IPC_SID_AUTH_CORE_HOLD_PASS","IPC_BAD_INTENT_DENIED") else 3)
