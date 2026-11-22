"""Real Windows TerminateProcess during one open unified admission transaction."""
import sys,os,time,json,sqlite3,subprocess,tempfile,ctypes
from ctypes import wintypes
from pathlib import Path
try:
    from .unified_admission import init,connect
except ImportError:
    from unified_admission import init,connect
def kill(pid):
 k=ctypes.WinDLL("kernel32",use_last_error=True)
 k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];k.OpenProcess.restype=wintypes.HANDLE
 k.TerminateProcess.argtypes=[wintypes.HANDLE,wintypes.UINT];k.TerminateProcess.restype=wintypes.BOOL
 k.CloseHandle.argtypes=[wintypes.HANDLE];k.CloseHandle.restype=wintypes.BOOL
 h=k.OpenProcess(0x0001,False,pid)
 if not h:raise RuntimeError("OPEN_PROCESS")
 try:
  if not k.TerminateProcess(h,173):raise RuntimeError("TERMINATE")
 finally:k.CloseHandle(h)
def child(path,gate):
 with connect(path) as db:
  db.execute("BEGIN IMMEDIATE")
  db.execute("""INSERT INTO unified_admissions VALUES
  ('g','h','b','s','a',9999999999,'PREPARED','container',NULL,'image',NULL,NULL,0)""")
  with open(gate,"xb",buffering=0) as f:f.write(b"ADMISSION_INSERTED_BEFORE_EXECUTION_RECORD");f.flush();os.fsync(f.fileno())
  time.sleep(60)
  db.execute("INSERT INTO unified_transitions VALUES ('g',1,NULL,'PREPARED')")
  db.commit()
def parent(root):
 root=Path(root);root.mkdir(exist_ok=False);db=root/"unified.sqlite";gate=root/"gate";init(db)
 p=subprocess.Popen([sys.executable,"-B",__file__,"child",str(db),str(gate)])
 limit=time.monotonic()+10
 while not gate.exists():
  if p.poll() is not None:raise RuntimeError("CHILD_EXIT")
  if time.monotonic()>limit:raise RuntimeError("GATE_TIMEOUT")
  time.sleep(.03)
 kill(p.pid);exit_code=p.wait(timeout=10)
 with connect(db) as c:
  admission=c.execute("SELECT COUNT(*) FROM unified_admissions").fetchone()[0]
  execution=c.execute("SELECT COUNT(*) FROM unified_transitions").fetchone()[0]
  integrity=c.execute("PRAGMA integrity_check").fetchone()[0]
 result={"pid":p.pid,"exit_code":exit_code,"admission_rows":admission,"execution_rows":execution,"integrity":integrity,
         "atomic_rollback":admission==execution==0 and integrity=="ok","scope":"synthetic unified transaction; not Guardian/Docker"}
 (root/"result.json").write_text(json.dumps(result,indent=2));print(json.dumps(result))
if __name__=="__main__":
 if sys.argv[1]=="child":child(Path(sys.argv[2]),Path(sys.argv[3]))
 else:parent(sys.argv[2])
