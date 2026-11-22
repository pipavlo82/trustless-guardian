"""Local-only Guardian IPC proof: AppContainer SID-gated Windows named pipe.

Does NOT issue execution grants or invoke Docker. Never accepts arbitrary tool paths.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys

G = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(G))
from guardian.windows import token_info

k=c.WinDLL("kernel32",use_last_error=True)
a=c.WinDLL("advapi32",use_last_error=True)
P=c.c_void_p
INVALID=P(-1).value

def api(lib,name,restype,*types):
    f=getattr(lib,name);f.restype=restype;f.argtypes=list(types);return f
create_pipe=api(k,"CreateNamedPipeW",w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,w.DWORD,P)
connect_pipe=api(k,"ConnectNamedPipe",w.BOOL,w.HANDLE,P)
read_pipe=api(k,"ReadFile",w.BOOL,w.HANDLE,P,w.DWORD,c.POINTER(w.DWORD),P)
write_pipe=api(k,"WriteFile",w.BOOL,w.HANDLE,P,w.DWORD,c.POINTER(w.DWORD),P)
close=api(k,"CloseHandle",w.BOOL,w.HANDLE)
disconnect=api(k,"DisconnectNamedPipe",w.BOOL,w.HANDLE)
impersonate=api(a,"ImpersonateNamedPipeClient",w.BOOL,w.HANDLE)
revert=api(a,"RevertToSelf",w.BOOL)
thread=api(k,"GetCurrentThread",w.HANDLE)
open_token=api(a,"OpenThreadToken",w.BOOL,w.HANDLE,w.DWORD,w.BOOL,c.POINTER(w.HANDLE))
get_token=api(a,"GetTokenInformation",w.BOOL,w.HANDLE,c.c_int,P,w.DWORD,c.POINTER(w.DWORD))
sid_string=api(a,"ConvertSidToStringSidW",w.BOOL,P,c.POINTER(w.LPWSTR))
free_local=api(k,"LocalFree",P,P)
convert=api(a,"ConvertStringSecurityDescriptorToSecurityDescriptorW",w.BOOL,w.LPCWSTR,w.DWORD,c.POINTER(P),c.POINTER(w.DWORD))

class SECURITY_ATTRIBUTES(c.Structure):
    _fields_=[("nLength",w.DWORD),("lpSecurityDescriptor",P),("bInheritHandle",w.BOOL)]

def check(ok,where):
    if not ok: raise OSError(where+": "+str(c.get_last_error()))

def token_query(handle,tag):
    length=w.DWORD(0)
    get_token(handle,tag,None,0,c.byref(length))
    if not 4<=length.value<=65536:raise RuntimeError("TOKEN_INFO_LENGTH")
    buf=c.create_string_buffer(length.value)
    check(get_token(handle,tag,buf,length,c.byref(length)),"GetTokenInformation")
    return buf

def client_identity(pipe):
    check(impersonate(pipe),"ImpersonateNamedPipeClient")
    h=w.HANDLE()
    try:
        check(open_token(thread(),8,True,c.byref(h)),"OpenThreadToken")
        is_app=bool(c.cast(token_query(h,29),c.POINTER(w.DWORD))[0])
        count=int(c.cast(token_query(h,30),c.POINTER(w.DWORD))[0])
        sb=token_query(h,31)
        sid=c.cast(sb,c.POINTER(P))[0]
        out=w.LPWSTR()
        if not sid and not is_app:
            return {"appcontainer":False,"capability_count":count,"sid":""}
        if not sid: raise RuntimeError("NO_APPCONTAINER_SID")
        check(sid_string(sid,c.byref(out)),"ConvertSidToStringSidW")
        try:
            value=out.value
        finally:free_local(out)
        return {"appcontainer":is_app,"capability_count":count,"sid":value}
    finally:
        if h:close(h)
        check(revert(),"RevertToSelf")

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")

def receive(pipe):
    buf=c.create_string_buffer(8192)
    n=w.DWORD()
    ok=read_pipe(pipe,buf,8192,c.byref(n),None)
    check(ok,"ReadFile")
    if not 1<=n.value<=4096:raise RuntimeError("IPC_FRAME_SIZE")
    return json.loads(buf.raw[:n.value].decode("utf-8"))

def send(pipe,data):
    encoded=canonical(data)
    if len(encoded)>4096:raise RuntimeError("IPC_REPLY_SIZE")
    buf=c.create_string_buffer(encoded)
    n=w.DWORD()
    check(write_pipe(pipe,buf,len(encoded),c.byref(n),None),"WriteFile")
    if n.value!=len(encoded):raise RuntimeError("IPC_SHORT_WRITE")

def serve(pipe_name,app_sid,ready_path,out_path):
    if not re.fullmatch(r"guardian-resonance-[0-9a-f]{24}",pipe_name):
        raise ValueError("PIPE_NAME")
    if not re.fullmatch(r"S-1-15-2-(?:[0-9]+-){6}[0-9]+",app_sid):
        raise ValueError("EXPECTED_APPCONTAINER_SID")
    owner=token_info()["user_sid"]
    sddl=("D:P(A;;GA;;;SY)(A;;GA;;;"+owner+")(A;;GRGW;;;"+app_sid+
          ")S:(ML;;NW;;;LW)")
    sd=P()
    check(convert(sddl,1,c.byref(sd),None),"ConvertSDDL")
    attr=SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES),sd,False)
    pipe=None
    result={
        "schema":"resonance.guardian-ipc-os-identity.v0",
        "channel":"WIN32_NAMED_PIPE",
        "broker_protocol":"SYNTHETIC_SIGNALS_AND_HOLD_ONLY",
        "expected_appcontainer_sid_sha256":hashlib.sha256(app_sid.encode()).hexdigest(),
        "production_ready":False,
        "guardian_grant_issued":False,
        "tool_executed":False,
        "verdict":"INCONCLUSIVE"
    }
    try:
        pipe=create_pipe(os.path.join(r"\\.\pipe",pipe_name),3,6,1,4096,4096,5000,c.byref(attr))
        if pipe==INVALID or not pipe:raise OSError("CreateNamedPipe:"+str(c.get_last_error()))
        ready_path.write_text("READY\n",encoding="ascii")
        if not connect_pipe(pipe,None):
            if c.get_last_error()!=535:raise OSError("ConnectNamedPipe:"+str(c.get_last_error()))
        hello=receive(pipe)
        ident=client_identity(pipe)
        result["client_identity"]={
            "appcontainer":ident["appcontainer"],
            "capability_count":ident["capability_count"],
            "sid_sha256":hashlib.sha256(ident["sid"].encode()).hexdigest()
        }
        if not ident["appcontainer"] or ident["capability_count"]!=0 or ident["sid"]!=app_sid:
            result["verdict"]="DENY_CLIENT_IDENTITY"
            send(pipe,{"schema":"guardian.ipc.v0","verdict":"DENY_CLIENT_IDENTITY"})
            return result
        if hello!={"op":"HELLO","schema":"resonance.ipc-client.v0","agent_id":"resonance-agent-v5"}:
            result["verdict"]="DENY_HELLO"
            send(pipe,{"schema":"guardian.ipc.v0","verdict":"DENY_HELLO"})
            return result
        nonce=secrets.token_hex(16)
        observations=[{key:value for key in ("cpu","memory","disk","hour_sin","hour_cos","solar_proxy","lunar_proxy")}
                      for value in (0.2,0.3,0.4)]
        send(pipe,{"schema":"guardian.ipc.v0","verdict":"SYNTHETIC_OBSERVATIONS",
                   "nonce":nonce,"observations":observations,"tools_enabled":False})
        proposal=receive(pipe)
        ident2=client_identity(pipe)
        if ident2!=ident:raise RuntimeError("IDENTITY_CHANGED")
        result["client_docker_pipe_errors"]=proposal.get("docker_errors")
        result["client_requested_tool"]=proposal.get("tool")
        expected={"op":"PROPOSE_TOOL","schema":"resonance.ipc-client.v0",
                 "nonce":nonce,"agent_id":"resonance-agent-v5",
                 "tool":"resonance.synthetic-hash-only.v0",
                 "resource_id":"resonance-synthetic-observation-v0",
                 "decision":"OBSERVE","ticks":3,
                 "docker_errors":{"linux":5,"legacy":5}}
        if proposal!=expected:
            result["verdict"]="DENY_REQUEST_OR_NONCE"
            send(pipe,{"schema":"guardian.ipc.v0","verdict":"DENY_REQUEST_OR_NONCE"})
        else:
            result["verdict"]="IPC_AUTHENTICATED_TOOL_HOLD"
            send(pipe,{"schema":"guardian.ipc.v0","verdict":"HOLD_GUARDIAN_GRANT_REQUIRED",
                       "grant_issued":False,"tool_executed":False})
        result["agent_ticks"]=proposal.get("ticks")
        result["nonce_binding_valid"]=proposal.get("nonce")==nonce
        result["nonce_replay_test"]="NOT_COVERED_SINGLE_CONNECTION"
        return result
    except (OSError,ValueError,RuntimeError,json.JSONDecodeError) as e:
        result["verdict"]="CONTROL_BROKEN"
        result["error_type"]=type(e).__name__
        result["error"]=str(e)[:230]
        return result
    finally:
        if pipe and pipe!=INVALID:
            try:disconnect(pipe)
            except Exception:pass
            close(pipe)
        free_local(sd)
        if out_path.exists(): raise RuntimeError("BROKER_REPORT_EXISTS")
        out_path.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"verdict":result["verdict"],"client":result.get("client_identity"),"out":str(out_path)}),flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--name",required=True)
    p.add_argument("--app-sid",required=True)
    p.add_argument("--ready",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    q=p.parse_args()
    response=serve(q.name,q.app_sid,q.ready,q.out)
    raise SystemExit(0 if response["verdict"]=="IPC_AUTHENTICATED_TOOL_HOLD" else 3)
