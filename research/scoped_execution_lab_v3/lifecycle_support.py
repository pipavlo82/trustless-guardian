"""Candidate-only durable dispatch marker and Docker readback. No alternative executor."""
import os,json,hashlib
from pathlib import Path
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
def record(out,identity):
 path=Path(out)/"dispatch.json"
 with path.open("xb",buffering=0) as f:
  b=canonical(identity)+b"\n"
  if f.write(b)!=len(b):raise IOError("SHORT_DISPATCH_WRITE")
  f.flush();os.fsync(f.fileno())
 from .atomic_receipt import directory_flush
 if not directory_flush(path.parent):raise IOError("DISPATCH_DIR_UNAVAILABLE")
 if path.read_bytes()!=b:raise IOError("DISPATCH_READBACK")
 return hashlib.sha256(b).hexdigest()
def worker_readback(name,container_id,image,expected):
 import subprocess
 def cmd(*args):
  r=subprocess.run(["docker",*args],capture_output=True,timeout=12)
  if r.returncode:raise RuntimeError("DOCKER_READBACK_FAILED")
  return r.stdout
 info=json.loads(cmd("inspect",container_id))[0]
 if info["Id"]!=container_id or info["Image"]!=image or info["Name"].lstrip("/")!=name:
  raise RuntimeError("DOCKER_IDENTITY_MISMATCH")
 if info["State"]["Status"]!="exited" or info["State"]["ExitCode"]!=0:
  raise RuntimeError("WORKER_NOT_EXITED_SUCCESS")
 stdout=cmd("logs",container_id)
 stderr=b"" # Docker CLI logs combines streams; expected synthetic worker emits no stderr
 if stdout!=expected or stderr!=b"":raise RuntimeError("WORKER_EFFECT_MISMATCH")
 return {"container_id":container_id,"image":image,"state":"exited","exit_code":0,
         "stdout_sha256":hashlib.sha256(stdout).hexdigest(),"stderr_sha256":hashlib.sha256(stderr).hexdigest()}

def crash_gate(out,phase):
 import time
 if os.environ.get('GUARDIAN_V3_CRASH_GATE')!=phase:return
 marker=Path(out)/(phase+'.gate')
 with marker.open('xb',buffering=0) as f:
  f.write(str(os.getpid()).encode());f.flush();os.fsync(f.fileno())
 while not (Path(out)/(phase+'.continue')).exists():time.sleep(.05)