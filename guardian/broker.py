"""Fixed-resource Windows broker. The agent never supplies a filesystem target."""
import base64
import ctypes as c
from ctypes import wintypes as w
from pathlib import Path
import sqlite3
from . import windows as win
from .policy import canonical,digest,parse,evaluate
from .evidence import seal


class FILEINFO(c.Structure):
    _fields_=[('attributes',w.DWORD),('creation',w.FILETIME),('access',w.FILETIME),('write',w.FILETIME),
              ('volume',w.DWORD),('size_high',w.DWORD),('size_low',w.DWORD),('links',w.DWORD),('index_high',w.DWORD),('index_low',w.DWORD)]


class LockedFile:
    def __init__(self,path,write=False):
        create=win.api(win.k,'CreateFileW',w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,win.P,w.DWORD,w.DWORD,w.HANDLE)
        self.handle=create(str(path),0x80000000|(0x40000000 if write else 0),0,None,3,0x00200000,None)
        if self.handle==c.c_void_p(-1).value:raise c.WinError(c.get_last_error())
        try:
            info=FILEINFO();win.check(win.api(win.k,'GetFileInformationByHandle',w.BOOL,w.HANDLE,c.POINTER(FILEINFO))(self.handle,c.byref(info)))
            if info.attributes & 0x400 or info.links!=1:raise ValueError('REPARSE_OR_HARDLINK')  # GUARD filetype
            self.identity=[info.volume,info.index_high,info.index_low]
        except Exception:self.close();raise

    def read(self):
        win.check(win.api(win.k,'SetFilePointerEx',w.BOOL,w.HANDLE,c.c_longlong,win.P,w.DWORD)(self.handle,0,None,0))
        buf=c.create_string_buffer(65537);count=w.DWORD()
        win.check(win.api(win.k,'ReadFile',w.BOOL,w.HANDLE,win.P,w.DWORD,c.POINTER(w.DWORD),win.P)(self.handle,buf,65537,c.byref(count),None))
        if count.value>65536:raise ValueError('RESOURCE_TOO_LARGE')
        return buf.raw[:count.value]

    def replace(self,raw):
        win.check(win.api(win.k,'SetFilePointerEx',w.BOOL,w.HANDLE,c.c_longlong,win.P,w.DWORD)(self.handle,0,None,0))
        count=w.DWORD();buf=c.create_string_buffer(raw)
        win.check(win.api(win.k,'WriteFile',w.BOOL,w.HANDLE,win.P,w.DWORD,c.POINTER(w.DWORD),win.P)(self.handle,buf,len(raw),c.byref(count),None))
        if count.value!=len(raw):raise OSError('short write')
        win.check(win.api(win.k,'SetEndOfFile',w.BOOL,w.HANDLE)(self.handle))
        win.check(win.api(win.k,'FlushFileBuffers',w.BOOL,w.HANDLE)(self.handle))

    def close(self):
        if self.handle:win.close(self.handle);self.handle=None
    def __enter__(self):return self
    def __exit__(self,*_):self.close()


class Broker:
    def __init__(self,root,policy_sha256):
        self.root=Path(root).absolute();self.path=self.root/'secure/resource.txt'
        self.policy_path=self.root/'secure/policy.json';self.policy_sha256=policy_sha256
        with LockedFile(self.path) as f:self.identity=f.identity
        self.db_path=self.root/'secure/nonces.sqlite'
        with sqlite3.connect(self.db_path) as db:db.execute('CREATE TABLE IF NOT EXISTS consumed(nonce TEXT PRIMARY KEY)')

    def execute(self,request,principal,now,presented=None):
        if win.token_info()['appcontainer']:raise PermissionError('BROKER_TOKEN_REQUIRED')
        # Parent paths are fixed trusted configuration, not an agent path parameter.
        win.safe_path(self.root,self.path);win.safe_path(self.root,self.policy_path)
        with LockedFile(self.policy_path) as policy_file, LockedFile(self.path,write=True) as resource:
            policy_raw=policy_file.read();policy=parse(policy_raw)
            before=resource.read();before_hash=digest(before)
            db=sqlite3.connect(self.db_path,timeout=2)
            try:
                db.execute('BEGIN IMMEDIATE')
                used={r[0] for r in db.execute('SELECT nonce FROM consumed')}
                decision=evaluate(request,policy,principal,now,before_hash,used)
                if digest(policy_raw)!=self.policy_sha256 or policy_raw!=canonical(policy):  # GUARD policy_pin
                    decision={'status':'REFUTED','decision':'DENY','reason':'POLICY_CHANGED','scope':None}
                if resource.identity!=self.identity:  # GUARD resource_identity
                    decision={'status':'REFUTED','decision':'DENY','reason':'RESOURCE_IDENTITY','scope':None}
                outcome='NOT_EXECUTED'
                # No presented gateway/client verdict is used as permission.
                if decision['decision']=='ALLOW':  # GUARD enforcement
                    db.execute('INSERT INTO consumed VALUES(?)',(request['nonce'],));db.commit()
                    resource.replace(request['content'].encode('utf-8'));outcome='EXECUTED'
                else:db.rollback()
                after=resource.read()
                return seal({'request':request,'request_sha256':digest(canonical(request)),
                  'policy':policy,'policy_sha256':digest(policy_raw),'trusted_policy_sha256':self.policy_sha256,
                  'principal':principal,'verification_time':now,'used_nonces':sorted(used),'decision':decision,
                  'broker_result':outcome,'resource_identity':resource.identity,'trusted_resource_identity':self.identity,
                  'before_sha256':before_hash,'after_sha256':digest(after),
                  'before_base64':base64.b64encode(before).decode(),'after_base64':base64.b64encode(after).decode(),
                  'verification_metadata':{'profile':'guardian.local-file.v0','external_execution':'UNVERIFIABLE',
                                           'observation':'local broker handle; independently witnessed by laboratory harness'}})
            finally:db.close()
