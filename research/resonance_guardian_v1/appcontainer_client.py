"""Original Resonance State/decide inside zero-capability AppContainer.

Only a fixed, identity-scoped broker pipe; no files, Docker or shell actions.
"""
import ctypes as c
from ctypes import wintypes as w
import json
import os
import sys
import hashlib

import agent

k=c.WinDLL("kernel32",use_last_error=True)
def api(name,return_type,*args):
    f=getattr(k,name)
    f.restype=return_type; f.argtypes=list(args)
    return f
CreateFileW=api("CreateFileW",w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE)
ReadFile=api("ReadFile",w.BOOL,w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p)
WriteFile=api("WriteFile",w.BOOL,w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p)
CloseHandle=api("CloseHandle",w.BOOL,w.HANDLE)
BAD=c.c_void_p(-1).value

def pipe_open(name):
    handle=CreateFileW(os.path.join(r"\\.\pipe",name),0xc0000000,0,None,3,0,None)
    if handle==BAD:
        raise OSError("IPC_CONNECT_ERROR:"+str(c.get_last_error()))
    return handle

def direct_pipe_error(kind):
    name={"linux":"dockerDesktopLinuxEngine","legacy":"docker_engine"}[kind]
    handle=CreateFileW(os.path.join(r"\\.\pipe",name),0xc0000000,0,None,3,0,None)
    if handle!=BAD:
        CloseHandle(handle)
        return 0
    return c.get_last_error()

def send(handle,data):
    raw=json.dumps(data,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")
    if not 1<=len(raw)<=4096:raise RuntimeError("CLIENT_MESSAGE_SIZE")
    b=c.create_string_buffer(raw)
    size=w.DWORD()
    if not WriteFile(handle,b,len(raw),c.byref(size),None) or size.value!=len(raw):
        raise OSError("IPC_WRITE_ERROR:"+str(c.get_last_error()))

def recv(handle):
    b=c.create_string_buffer(8192)
    size=w.DWORD()
    if not ReadFile(handle,b,8192,c.byref(size),None):
        raise OSError("IPC_READ_ERROR:"+str(c.get_last_error()))
    if not 1<=size.value<=4096:raise RuntimeError("IPC_REPLY_SIZE")
    return json.loads(b.raw[:size.value].decode("utf-8"))

def run(pipe_name,mode="normal"):
    if mode not in ("normal","bad_nonce","bad_tool"):return 70
    docker={"linux":direct_pipe_error("linux"),"legacy":direct_pipe_error("legacy")}
    if docker!={"linux":5,"legacy":5}:return 76
    if not pipe_name.startswith("guardian-resonance-"):return 77
    try:
        handle=pipe_open(pipe_name)
    except OSError as exc:
        return 86 if str(exc)=="IPC_CONNECT_ERROR:2" else 98
    try:
        send(handle,{"op":"HELLO","schema":"resonance.ipc-client.v0","agent_id":"resonance-agent-v5"})
        answer=recv(handle)
        if answer.get("schema")!="guardian.ipc.v0" or answer.get("verdict")!="SYNTHETIC_OBSERVATIONS" or answer.get("tools_enabled") is not False:
            return 78
        signals=answer.get("observations")
        if type(signals) is not list or len(signals)!=3:return 79
        s=agent.State()
        d=None
        for row in signals:
            if type(row) is not dict or set(row)!=set(agent.FIELDS):return 80
            if any(type(x) not in (int,float) or not 0<=x<=1 for x in row.values()):return 81
            s,d=agent.decide(s,row)
        if s.step!=3 or d["action"]!="OBSERVE":return 82
        proposal={
            "op":"PROPOSE_TOOL",
            "schema":"resonance.ipc-client.v0",
            "nonce":answer["nonce"],
            "agent_id":"resonance-agent-v5",
            "tool":"resonance.synthetic-hash-only.v0",
            "resource_id":"resonance-synthetic-observation-v0",
            "decision":d["action"],
            "ticks":s.step,
            "docker_errors":docker
        }
        if mode=="bad_nonce":proposal["nonce"]="0"*32
        if mode=="bad_tool":proposal["tool"]="shell"
        send(handle,proposal)
        reply=recv(handle)
        if mode!="normal":
            return 75 if reply=={"schema":"guardian.ipc.v0","verdict":"DENY_REQUEST_OR_NONCE"} else 85
        if reply!={"schema":"guardian.ipc.v0","verdict":"HOLD_GUARDIAN_GRANT_REQUIRED","grant_issued":False,"tool_executed":False}:return 83
        return 73
    finally:
        CloseHandle(handle)

if __name__=="__main__":
    if len(sys.argv)!=3:sys.exit(71)
    try:sys.exit(run(sys.argv[1],sys.argv[2]))
    except Exception:sys.exit(99)
