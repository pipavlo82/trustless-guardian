"""Candidate Guardian state adapter: admission and lifecycle share ONE SQLite WAL file.
All authority checks remain in lab.execute BEFORE prepare_admission.
"""
import secrets,time,sqlite3
from pathlib import Path
from .unified_admission import init,prepare,advance,connect
from research.auth_gateway_v1.errors import SecurityError
class UnifiedState:
 def __init__(self,path,scope):
  self.path=Path(path);self.scope=scope;init(self.path)
 def close(self):pass
 def prepare_admission(self,grant_id,grant_sha256,binding_sha256,owner_session,attempt_id,now,expires_at):
  name="guardian-scoped-lab-"+secrets.token_hex(12)
  identity={"grant_id":grant_id,"grant_sha256":grant_sha256,"binding_sha256":binding_sha256,
   "owner_session":owner_session,"attempt_id":attempt_id,"expires_at":expires_at,
   "container_name":name,"image":"sha256:c7363bd6adf6d1465f0057c1c1f73586fd16e55eeec614b6e670d00989c43059"}
  try:prepare(self.path,identity)
  except (sqlite3.IntegrityError,ValueError) as e:raise SecurityError("GRANT_REPLAY_OR_ADMISSION_REFUSED") from e
  return {"scope":self.scope,"grant_id":grant_id,"attempt_id":attempt_id,"owner_session":owner_session,
   "state":"PREPARED","container_name":name}
 def mark_committed(self,claim,now,outcome_sha256,exit_code):
  # Final CAS is performed by lab's lifecycle transition. This verifies it.
  with connect(self.path) as db:
   row=db.execute("SELECT state FROM unified_admissions WHERE grant_id=? AND attempt_id=? AND owner_session=?",
    (claim["grant_id"],claim["attempt_id"],claim["owner_session"])).fetchone()
  if not row or row[0]!="COMMITTED":raise SecurityError("UNIFIED_COMMIT_NOT_CONFIRMED")
 def mark_recovery_required(self,claim,now,outcome_sha256):
  with connect(self.path) as db:
   db.execute("BEGIN IMMEDIATE")
   changed=db.execute("UPDATE unified_admissions SET state='RECOVERY_REQUIRED' WHERE grant_id=? AND attempt_id=? AND state IN ('PREPARED','DISPATCH_RECORDED','RESULT_OBSERVED')",
    (claim["grant_id"],claim["attempt_id"])).rowcount
   if changed!=1:raise SecurityError("UNIFIED_RECOVERY_TRANSITION")
   db.commit()
