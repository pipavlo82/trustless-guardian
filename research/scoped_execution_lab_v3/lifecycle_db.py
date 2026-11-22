"""V3 candidate-only transactional execution state. SQLite WAL FULL, fail closed.
Does not authorize execution; existing Guardian admission/grant gate remains authoritative.
"""
import sqlite3,hashlib,json,time
from pathlib import Path
STATES=("PREPARED","DISPATCH_RECORDED","RESULT_OBSERVED","RECEIPT_PUBLISHED","COMMITTED")
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def connect(path):
 db=sqlite3.connect(str(path),timeout=5,isolation_level=None)
 db.execute("PRAGMA busy_timeout=5000")
 mode=db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
 if mode.lower()!="wal":raise RuntimeError("WAL_UNAVAILABLE")
 db.execute("PRAGMA synchronous=FULL")
 return db
def initialize(path):
 with connect(path) as db:
  db.execute("""CREATE TABLE IF NOT EXISTS execution_lifecycle(
    grant_id TEXT PRIMARY KEY,request_sha256 TEXT NOT NULL,grant_sha256 TEXT NOT NULL,
    attempt_id TEXT NOT NULL,container_id TEXT NOT NULL,image TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('PREPARED','DISPATCH_RECORDED','RESULT_OBSERVED','RECEIPT_PUBLISHED','COMMITTED')),
    outcome_sha256 TEXT,receipt_sha256 TEXT,updated_ns INTEGER NOT NULL) STRICT""")
  db.execute("""CREATE TABLE IF NOT EXISTS execution_transitions(
    grant_id TEXT NOT NULL,ordinal INTEGER NOT NULL,prior_state TEXT,new_state TEXT NOT NULL,
    row_sha256 TEXT NOT NULL,PRIMARY KEY(grant_id,ordinal)) STRICT""")
def transition(path,identity,expected,new_state,outcome=None,receipt=None):
 if new_state not in STATES:raise ValueError("STATE")
 if (expected,new_state) not in ((None,"PREPARED"),("PREPARED","DISPATCH_RECORDED"),("DISPATCH_RECORDED","RESULT_OBSERVED"),("RESULT_OBSERVED","RECEIPT_PUBLISHED"),("RECEIPT_PUBLISHED","COMMITTED")):raise ValueError("TRANSITION")
 required=("grant_id","request_sha256","grant_sha256","attempt_id","container_id","image")
 if set(identity)!=set(required) or any(not isinstance(identity[k],str) or not identity[k] for k in required):raise ValueError("IDENTITY")
 if new_state in ("RESULT_OBSERVED","RECEIPT_PUBLISHED","COMMITTED") and (not outcome or len(outcome)!=64):raise ValueError("OUTCOME_REQUIRED")
 if new_state in ("RECEIPT_PUBLISHED","COMMITTED") and (not receipt or len(receipt)!=64):raise ValueError("RECEIPT_REQUIRED")
 with connect(path) as db:
  db.execute("BEGIN IMMEDIATE")
  old=db.execute("SELECT request_sha256,grant_sha256,attempt_id,container_id,image,state,outcome_sha256,receipt_sha256 FROM execution_lifecycle WHERE grant_id=?",(identity["grant_id"],)).fetchone()
  if expected is None:
   if old is not None:raise ValueError("REPLAY")
   db.execute("INSERT INTO execution_lifecycle VALUES (?,?,?,?,?,?,?,?,?,?)",(
    identity["grant_id"],identity["request_sha256"],identity["grant_sha256"],identity["attempt_id"],identity["container_id"],identity["image"],new_state,None,None,time.time_ns()))
   ordinal=1
  else:
   if old is None or old[:5]!=tuple(identity[k] for k in required[1:]) or old[5]!=expected:raise ValueError("CAS_OR_IDENTITY")
   if old[6] is not None and old[6]!=outcome:raise ValueError("OUTCOME_SUBSTITUTION")
   if old[7] is not None and old[7]!=receipt:raise ValueError("RECEIPT_SUBSTITUTION")
   changed=db.execute("UPDATE execution_lifecycle SET state=?,outcome_sha256=COALESCE(?,outcome_sha256),receipt_sha256=COALESCE(?,receipt_sha256),updated_ns=? WHERE grant_id=? AND state=?",(new_state,outcome,receipt,time.time_ns(),identity["grant_id"],expected)).rowcount
   if changed!=1:raise ValueError("CAS")
   ordinal=STATES.index(new_state)+1
  row_hash=hashlib.sha256(canonical({"identity":identity,"expected":expected,"state":new_state,"outcome":outcome,"receipt":receipt})).hexdigest()
  db.execute("INSERT INTO execution_transitions VALUES (?,?,?,?,?)",(identity["grant_id"],ordinal,expected,new_state,row_hash))
  db.commit()
 return new_state
def status(path,grant_id):
 with connect(path) as db:
  return db.execute("SELECT state,outcome_sha256,receipt_sha256 FROM execution_lifecycle WHERE grant_id=?",(grant_id,)).fetchone()
