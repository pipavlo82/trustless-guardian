"""Candidate-only hardened reconciliation for unified V3 crash evidence.
Independent verifier, bounded Docker readback; never invokes Docker create/start.
No external anchor or universal rollback protection is claimed.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import sqlite3
import time
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from research.checkpoint_enforcement.gate import protected, recheck_current

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
try:
    from .verify_unified_independent import verify,read,canon,sha
except ImportError:
    from verify_unified_independent import verify,read,canon,sha

def gate(folder, stage):
    wanted=os.environ.get("GUARDIAN_RECON_CRASH_GATE")
    if stage!=wanted: return
    marker=Path(folder)/("reconcile-"+stage+".gate")
    with marker.open("xb",buffering=0) as f:
        value=canon({"pid":os.getpid(),"stage":stage})+b"\n"
        f.write(value);f.flush();os.fsync(f.fileno())
    while not (Path(folder)/("reconcile-"+stage+".continue")).exists():
        time.sleep(.05)

@protected('recovery', lambda args, kw: args[0] if args else kw['root'])
def reconcile(root):
    root=Path(root).resolve()
    def fail(status,reason):
        return dict(status=status,reason=reason,dispatches=0)
    try:
        pre=verify(root)
        if pre.get("status")!="RECOVERY_REQUIRED" or pre.get("state") not in ("RESULT_OBSERVED","RECEIPT_PUBLISHED"):
            return fail("HOLD","NOT_RECONCILABLE")
        job=root/"job"
        paths=[job/name for name in ("receipt.json","grant.json","request.json","dispatch.json","outcome.json","expectations.json","stdout.bin","stderr.bin")]
        if not all(p.is_file() for p in paths):
            return fail("RECOVERY_REQUIRED","EVIDENCE_INCOMPLETE")
        hashes={str(p):sha(p.read_bytes()) for p in paths}
        receipt,grant,request,dispatch,outcome,ex=(read(job/name) for name in
            ("receipt.json","grant.json","request.json","dispatch.json","outcome.json","expectations.json"))
        r,g=receipt["payload"],grant["payload"]
        for signed,public in ((receipt,ex["receipt_public"]),(grant,ex["grant_public"])):
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
                base64.b64decode(signed["signature"],validate=True),canon(signed["payload"]))
        stdout=(job/"stdout.bin").read_bytes();stderr=(job/"stderr.bin").read_bytes()
        expected_stdout=canon({"action":"synthetic_request_hash",
            "request_file_sha256":sha(canon(request)+b"\n"),"uid":65534})+b"\n"
        if (stdout!=expected_stdout or stderr!=b"" or
            r["receipt_id"]=="" or r["lifecycle"]!="COMMITTED" or
            r["classification"]!="EXECUTED" or r["container_started"] is not True or
            outcome["container_started"] is not True or outcome["witnessed"] is not True or
            outcome["exit_code"]!=0 or outcome["timed_out"] is not False or
            r["exit_code"]!=0 or r["request_id"]!=request["request_id"] or
            r["grant_id"]!=g["grant_id"] or r["grant_id"]!=dispatch["grant_id"] or
            r["grant_sha256"]!=dispatch["grant_sha256"] or
            r["request_sha256"]!=dispatch["request_sha256"] or
            g["binding_sha256"]!=dispatch["request_sha256"] or
            r["grant_sha256"]!=sha(canon(grant)) or
            r["outcome_sha256"]!=sha(canon(outcome)) or
            r["stdout_sha256"]!=sha(stdout) or
            r["stderr_sha256"]!=sha(stderr) or
            r["image_identity"]!=dispatch["image"] or
            r["worker_sha256"]!=dispatch["worker_sha256"] or
            outcome["container_id"]!=dispatch["container_id"] or
            outcome["container_name"]!=dispatch["container_name"]):
            return fail("UNKNOWN/HOLD","CROSS_SOURCE_BINDING")
        effect=sha(canon({"container_id":dispatch["container_id"],
            "stdout_sha256":sha(stdout),"stderr_sha256":sha(stderr),"exit_code":0}))
        receipt_hash=sha((job/"receipt.json").read_bytes())
        dbpath=root/"state.sqlite"
        with sqlite3.connect(dbpath,timeout=10,isolation_level=None) as db:
            if db.execute("PRAGMA journal_mode").fetchone()[0].lower()!="wal":
                return fail("UNKNOWN/HOLD","WAL_REQUIRED")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("""SELECT state,grant_sha256,binding_sha256,attempt_id,
                container_id,container_name,image,outcome_sha256,receipt_sha256
                FROM unified_admissions WHERE grant_id=?""",(r["grant_id"],)).fetchone()
            if (row is None or row[0] not in ("RESULT_OBSERVED","RECEIPT_PUBLISHED") or
                row[1]!=dispatch["grant_sha256"] or row[2]!=dispatch["request_sha256"] or
                row[3]!=r["receipt_id"] or row[4]!=dispatch["container_id"] or
                row[5]!=dispatch["container_name"] or row[6]!=dispatch["image"] or
                row[7]!=effect or (row[0]=="RECEIPT_PUBLISHED" and row[8]!=receipt_hash)):
                db.rollback()
                return fail("UNKNOWN/HOLD","DB_CAS_OR_IDENTITY")
            for p in paths:
                if sha(p.read_bytes())!=hashes[str(p)]:
                    db.rollback()
                    return fail("UNKNOWN/HOLD","EVIDENCE_CHANGED")
            if row[0]=="RESULT_OBSERVED":
                n=db.execute("""UPDATE unified_admissions
                    SET state='RECEIPT_PUBLISHED',receipt_sha256=?,updated_ns=?
                    WHERE grant_id=? AND state='RESULT_OBSERVED' AND attempt_id=?
                    AND outcome_sha256=? AND container_id=?""",
                    (receipt_hash,time.time_ns(),r["grant_id"],r["receipt_id"],effect,dispatch["container_id"])).rowcount
                if n!=1: raise ValueError("RECEIPT_CAS")
                db.execute("INSERT INTO unified_transitions VALUES (?,?,?,?)",
                    (r["grant_id"],4,"RESULT_OBSERVED","RECEIPT_PUBLISHED"))
            n=db.execute("""UPDATE unified_admissions SET state='COMMITTED',updated_ns=?
                WHERE grant_id=? AND attempt_id=? AND state='RECEIPT_PUBLISHED'
                AND receipt_sha256=? AND outcome_sha256=?""",
                (time.time_ns(),r["grant_id"],r["receipt_id"],receipt_hash,effect)).rowcount
            if n!=1:raise ValueError("COMMIT_CAS")
            db.execute("INSERT INTO unified_transitions VALUES (?,?,?,?)",
                (r["grant_id"],5,"RECEIPT_PUBLISHED","COMMITTED"))
            gate(root,"before_commit")
            recheck_current('before_reconciliation_commit')
            db.commit()
        gate(root,"after_commit")
        post=verify(root)
        if post.get("status")!="LOCAL_CONFIRMED_EXTERNAL_HOLD":
            return fail("UNKNOWN/HOLD","POST_COMMIT_REVERIFY")
        return fail("LOCAL_RECONCILED_EXTERNAL_HOLD","NO_INDEPENDENT_ANCHOR")
    except Exception as e:
        return fail("UNKNOWN/HOLD",type(e).__name__+":"+str(e))

if __name__=="__main__":
    arg=argparse.ArgumentParser();arg.add_argument("root");arg.add_argument("--json",action="store_true")
    args=arg.parse_args();value=reconcile(args.root);print(json.dumps(value,sort_keys=True))
    raise SystemExit(0 if value["status"]=="LOCAL_RECONCILED_EXTERNAL_HOLD" else 2)
