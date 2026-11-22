"""Independent V3 unified SQLite + Docker readback verifier. No Guardian/Core imports.
Never creates/starts Docker. External anchor remains unverified.
"""
import sys,json,sqlite3,hashlib,base64,subprocess,os,time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
STATES=("PREPARED","DISPATCH_RECORDED","RESULT_OBSERVED","RECEIPT_PUBLISHED","COMMITTED")
def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):
 b=Path(p).read_bytes();o=json.loads(b)
 if b!=canon(o)+b"\n":raise ValueError("NONCANONICAL")
 return o
def verify(root):
 root=Path(root);job=root/"job"
 if os.environ.get('GUARDIAN_UNIFIED_RECOVERY_CRASH_GATE')=='1':
  gate=root/'unified_recovery.gate'
  with gate.open('xb',buffering=0) as f:f.write(str(os.getpid()).encode());f.flush();os.fsync(f.fileno())
  while not (root/'unified_recovery.continue').exists():time.sleep(.05)
 with sqlite3.connect(f"file:{(root/'state.sqlite').as_posix()}?mode=ro",uri=True) as db:
  if db.execute("PRAGMA integrity_check").fetchone()[0]!="ok":raise ValueError("SQLITE_INTEGRITY")
  if db.execute("PRAGMA journal_mode").fetchone()[0].lower()!="wal":raise ValueError("NOT_WAL")
  rows=db.execute("SELECT grant_id,grant_sha256,binding_sha256,state,container_id,image,outcome_sha256,receipt_sha256 FROM unified_admissions").fetchall()
  if len(rows)!=1:raise ValueError("ADMISSION_COUNT")
  row=rows[0];trans=db.execute("SELECT ordinal,prior_state,new_state FROM unified_transitions ORDER BY ordinal").fetchall()
  if trans!=[(i+1,STATES[i-1] if i else None,STATES[i]) for i in range(STATES.index(row[3])+1)]:raise ValueError("STATE_CHAIN")
 dispatch=read(job/"dispatch.json")
 if (dispatch["grant_id"],dispatch["grant_sha256"],dispatch["request_sha256"],dispatch["container_id"],dispatch["image"])!=(row[0],row[1],row[2],row[4],row[5]):raise ValueError("DISPATCH_BINDING")
 if not (job/"receipt.json").exists():return {"status":"RECOVERY_REQUIRED","state":row[3],"dispatches":0}
 receipt=read(job/"receipt.json");grant=read(job/"grant.json");request=read(job/"request.json");outcome=read(job/"outcome.json");ex=read(job/"expectations.json")
 for signed,pub in ((receipt,ex["receipt_public"]),(grant,ex["grant_public"])):
  Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(base64.b64decode(signed["signature"],validate=True),canon(signed["payload"]))
 r=receipt["payload"];g=grant["payload"]
 if r["grant_id"]!=row[0] or r["request_id"]!=request["request_id"] or r["request_sha256"]!=row[2] or g["grant_id"]!=row[0]:raise ValueError("REQUEST_GRANT_BINDING")
 if r["outcome_sha256"]!=sha(canon(outcome)) or r["stdout_sha256"]!=sha((job/"stdout.bin").read_bytes()):raise ValueError("OUTCOME_BINDING")
 if row[3] in ("RECEIPT_PUBLISHED","COMMITTED") and row[7]!=sha((job/"receipt.json").read_bytes()):raise ValueError("RECEIPT_DIGEST")
 info=json.loads(subprocess.check_output(["docker","inspect",row[4]],timeout=12))[0]
 if info["Id"]!=row[4] or info["Image"]!=row[5]:raise ValueError("DOCKER_IDENTITY")
 if info["State"]["Status"]!="exited" or info["State"]["ExitCode"]!=0:raise ValueError("DOCKER_STATE")
 expected=canon({"action":"synthetic_request_hash","request_file_sha256":sha(canon(request)+b"\n"),"uid":65534})+b"\n"
 if subprocess.check_output(["docker","logs",row[4]],timeout=12)!=expected or (job/"stdout.bin").read_bytes()!=expected:raise ValueError("DOCKER_OUTPUT")
 return {"status":"LOCAL_CONFIRMED_EXTERNAL_HOLD" if row[3]=="COMMITTED" else "RECOVERY_REQUIRED","state":row[3],"dispatches":0}
if __name__=="__main__":
 try:print(json.dumps(verify(sys.argv[1])))
 except Exception as e:print(json.dumps({"status":"UNKNOWN/HOLD","reason":type(e).__name__+":"+str(e),"dispatches":0}));sys.exit(2)
