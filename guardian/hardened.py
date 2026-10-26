"""v02 broker: separate AppContainer, held directory/file identities, durable intent."""
import base64
import ctypes as c
from ctypes import wintypes as w
from contextlib import ExitStack
from pathlib import Path
from . import windows as win
from .broker import LockedFile, FILEINFO
from .recovery import Journal
from .policy import evaluate, parse, canonical, digest
from .evidence import seal
from .ipc import envelope


class Directory:
    def __init__(self,path,identity=None):
        self.handle=win.api(win.k,'CreateFileW',w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,win.P,w.DWORD,w.DWORD,w.HANDLE)(
            str(path),0x80,3,None,3,0x02000000|0x00200000,None)
        if self.handle==c.c_void_p(-1).value:raise c.WinError(c.get_last_error())
        try:
            info=FILEINFO();win.check(win.api(win.k,'GetFileInformationByHandle',w.BOOL,w.HANDLE,c.POINTER(FILEINFO))(self.handle,c.byref(info)))
            self.identity=[info.volume,info.index_high,info.index_low]
            if info.attributes & 0x400 or not info.attributes & 0x10:raise ValueError('DIRECTORY_REPARSE')
            if identity is not None and self.identity!=identity:raise ValueError('DIRECTORY_IDENTITY')  # V02 directory_identity
        except Exception:self.close();raise
    def close(self):
        if self.handle:win.close(self.handle);self.handle=None
    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def refusal(reason,status='REFUTED'):
    return {'status':status,'decision':'DENY','reason':reason,'scope':None,'execution':'NOT_EXECUTED'}


class HardenedBroker:
    def __init__(self,config):
        self.config=config;self.root=Path(config['root']);self.stack=ExitStack()
        token=win.token_info()
        if (not token['appcontainer'] or token['appcontainer_sid']!=config['broker_sid']
            or token['elevated'] or token['capability_count'] or token['integrity_sid']!='S-1-16-4096'):
            raise PermissionError('BROKER_IDENTITY')
        try:
            for name in ('.','secure','journal'):
                self.stack.enter_context(Directory(self.root/name,config['directories'][name]))
        except Exception:self.stack.close();raise
    def close(self):self.stack.close()
    def execute(self,raw,principal,now,hook=lambda *a:None):
        cfg=self.config;stage='NOT_STARTED'
        try:request=envelope(raw,cfg['policy_sha256'])
        except (ValueError,TypeError,UnicodeError,RecursionError):return refusal('IPC_SCHEMA')
        try:
            with LockedFile(self.root/'secure/policy.json') as pf, LockedFile(self.root/'secure/resource.txt',True) as rf:
                policy_raw=pf.read();policy=parse(policy_raw);before=rf.read()
                if digest(policy_raw)!=cfg['policy_sha256'] or policy_raw!=canonical(policy):return refusal('POLICY_CHANGED')  # V02 policy_pin
                if pf.identity!=cfg['policy_identity'] or rf.identity!=cfg['resource_identity']:return refusal('RESOURCE_IDENTITY')  # V02 resource_identity
                journal=Journal(self.root/'journal/operations.sqlite')
                try:
                    rows=journal.recover(before,rf.identity,cfg['policy_sha256'])
                    if any(r['state'] in ('PREPARED','RECOVERY_REQUIRED') for r in rows):return {**refusal('RECOVERY_REQUIRED','UNVERIFIABLE'),'execution':'RECOVERY_REQUIRED','retry_permitted':False}  # V02 recovery_gate
                    used={r['nonce'] for r in rows}
                    decision=evaluate(request,policy,principal,now,digest(before),used)
                    if decision['decision']!='ALLOW':return {**decision,'execution':'NOT_EXECUTED'}  # V02 enforcement
                    intended=request['content'].encode()
                    intent={'request_sha256':digest(canonical(request)),'policy_sha256':cfg['policy_sha256'],
                            'before_sha256':digest(before),'after_sha256':digest(intended),'resource_identity':rf.identity}
                    stage='PREPARING'
                    journal.prepare(request['nonce'],intent)
                    stage='PREPARED'
                    hook('PREPARED',rf,intended)
                    stage='WRITING'
                    rf.replace(intended)
                    stage='WRITTEN'
                    hook('WRITTEN',rf,intended)
                    after=rf.read()
                    if after!=intended:raise OSError('READBACK_MISMATCH')
                    receipt=seal({'profile':'guardian.local-file.v02','request':request,'policy':policy,
                      **intent,'principal':principal,'verification_time':now,'used_nonces':sorted(used),
                      'decision':decision,'before_base64':base64.b64encode(before).decode(),
                      'after_base64':base64.b64encode(after).decode(),'execution':'LOCAL_WRITE_OBSERVED',
                      'external_execution':'UNVERIFIABLE'})
                    stage='COMMITTING'
                    journal.commit(request['nonce'],receipt)
                    stage='COMMITTED'
                    hook('COMMITTED',rf,intended)
                    return {**decision,'execution':'COMMITTED','receipt':receipt}
                finally:journal.close()
        except Exception:  # V04 ordinary_exception_boundary
            if stage!='NOT_STARTED':  # V03 ambiguous_failure
                # A failure can follow a durable intent, partial write, or commit.
                # DENY here is a refusal to certify/retry, never evidence of no write.
                return {**refusal('EXECUTION_OUTCOME_UNCERTAIN','UNVERIFIABLE'),
                        'execution':'RECOVERY_REQUIRED','failure_stage':stage,'retry_permitted':False}
            return refusal('DEPENDENCY_OR_IO_FAILURE','UNVERIFIABLE')
