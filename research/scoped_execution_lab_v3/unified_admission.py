"""Candidate-only unified admission+PREPARED transaction in one SQLite WAL database.
Does not grant authority. Must only be called AFTER existing Guardian grant verification.
"""
import sqlite3,time,hashlib,json
from pathlib import Path
SCOPE="guardian.synthetic-hash.lab.v1"
def connect(path):
 db=sqlite3.connect(str(path),timeout=5,isolation_level=None)
 if db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower()!="wal":raise RuntimeError("WAL_UNAVAILABLE")
 db.execute("PRAGMA synchronous=FULL");db.execute("PRAGMA foreign_keys=ON");return db
def init(path):
 with connect(path) as db:
  db.execute("""CREATE TABLE IF NOT EXISTS unified_admissions(
   grant_id TEXT PRIMARY KEY,grant_sha256 TEXT NOT NULL,binding_sha256 TEXT NOT NULL,
   owner_session TEXT NOT NULL,attempt_id TEXT NOT NULL UNIQUE,expires_at INTEGER NOT NULL,
   state TEXT NOT NULL CHECK(state IN ('PREPARED','DISPATCH_RECORDED','RESULT_OBSERVED','RECEIPT_PUBLISHED','COMMITTED','RECOVERY_REQUIRED')),
   container_name TEXT NOT NULL UNIQUE,container_id TEXT UNIQUE,image TEXT NOT NULL,
   outcome_sha256 TEXT,receipt_sha256 TEXT,updated_ns INTEGER NOT NULL) STRICT""")
  db.execute("""CREATE TABLE IF NOT EXISTS unified_transitions(
   grant_id TEXT NOT NULL,ordinal INTEGER NOT NULL,prior_state TEXT,new_state TEXT NOT NULL,
   PRIMARY KEY(grant_id,ordinal),FOREIGN KEY(grant_id) REFERENCES unified_admissions(grant_id)) STRICT""")
def prepare(path,identity):
 required={"grant_id","grant_sha256","binding_sha256","owner_session","attempt_id","expires_at","container_name","image"}
 if set(identity)!=required:raise ValueError("SHAPE")
 if any(type(identity[k]) is not str or not identity[k] for k in required-{"expires_at"}):raise ValueError("IDENTITY")
 if type(identity["expires_at"]) is not int or identity["expires_at"]<=int(time.time()):raise ValueError("EXPIRED")
 with connect(path) as db:
  db.execute("BEGIN IMMEDIATE")
  db.execute("""INSERT INTO unified_admissions
   (grant_id,grant_sha256,binding_sha256,owner_session,attempt_id,expires_at,state,container_name,container_id,image,outcome_sha256,receipt_sha256,updated_ns)
   VALUES (?,?,?,?,?,?,'PREPARED',?,NULL,?,NULL,NULL,?)""",
   tuple(identity[k] for k in ("grant_id","grant_sha256","binding_sha256","owner_session","attempt_id","expires_at","container_name","image"))+(time.time_ns(),))
  db.execute("INSERT INTO unified_transitions VALUES (1,1,NULL,'PREPARED')".replace("VALUES (1,1,","VALUES (?,1,"),(identity["grant_id"],))
  db.commit()
def advance(path,grant_id,expected,new,container_id=None,outcome=None,receipt=None):
 edges={"PREPARED":"DISPATCH_RECORDED","DISPATCH_RECORDED":"RESULT_OBSERVED","RESULT_OBSERVED":"RECEIPT_PUBLISHED","RECEIPT_PUBLISHED":"COMMITTED"}
 if edges.get(expected)!=new:raise ValueError("INVALID_EDGE")
 if new=="DISPATCH_RECORDED" and not container_id:raise ValueError("CONTAINER_REQUIRED")
 if new in ("RESULT_OBSERVED","RECEIPT_PUBLISHED","COMMITTED") and not outcome:raise ValueError("OUTCOME_REQUIRED")
 if new in ("RECEIPT_PUBLISHED","COMMITTED") and not receipt:raise ValueError("RECEIPT_REQUIRED")
 with connect(path) as db:
  db.execute("BEGIN IMMEDIATE")
  row=db.execute("SELECT state,container_id,outcome_sha256,receipt_sha256 FROM unified_admissions WHERE grant_id=?",(grant_id,)).fetchone()
  if not row or row[0]!=expected:raise ValueError("CAS")
  if row[1] is not None and container_id is not None and row[1]!=container_id:raise ValueError("CONTAINER_SUBSTITUTION")
  if row[2] is not None and outcome is not None and row[2]!=outcome:raise ValueError("OUTCOME_SUBSTITUTION")
  if row[3] is not None and receipt is not None and row[3]!=receipt:raise ValueError("RECEIPT_SUBSTITUTION")
  n=db.execute("""UPDATE unified_admissions SET state=?,container_id=COALESCE(?,container_id),
    outcome_sha256=COALESCE(?,outcome_sha256),receipt_sha256=COALESCE(?,receipt_sha256),updated_ns=?
    WHERE grant_id=? AND state=?""",(new,container_id,outcome,receipt,time.time_ns(),grant_id,expected)).rowcount
  if n!=1:raise ValueError("CAS")
  ordinal=("PREPARED","DISPATCH_RECORDED","RESULT_OBSERVED","RECEIPT_PUBLISHED","COMMITTED").index(new)+1
  db.execute("INSERT INTO unified_transitions VALUES (?,?,?,?)",(grant_id,ordinal,expected,new))
  db.commit()
