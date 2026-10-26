"""Precisely scoped test faults in a disposable broker; never request fields."""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from guardian import windows as win
from guardian.hardened import HardenedBroker
from guardian.broker import LockedFile
from guardian.recovery import Journal
import v03_worker as worker
import v04_native as native

class InstrumentedBroker(HardenedBroker):
    def execute(self,raw,principal,now,hook=lambda *a:None):
        case=self.config.get('v04_fault');events=[]
        oldprepare=Journal.prepare;oldclose=Journal.close;oldapi=win.api
        def note(name,**extra):events.append({'boundary':name,**extra})
        def prepare(j,nonce,intent):
            if case=='journal_write_failure':j.db.execute('PRAGMA query_only=ON');note('sqlite_query_only_before_prepare')
            result=oldprepare(j,nonce,intent)
            if case=='prepare_return_failure':note('after_durable_prepare');raise RuntimeError('V04_PREPARE_RETURN')
            return result
        def close(j):
            oldclose(j)
            if case=='journal_close_failure':note('after_journal_close');raise RuntimeError('V04_CLOSE')
        def api(dll,name,result,*args):
            fn=oldapi(dll,name,result,*args)
            if case=='flush_failure' and name=='FlushFileBuffers':
                def fail(handle):
                    value=fn(w.HANDLE(0));note('FlushFileBuffers_invalid_handle',winerror=c.get_last_error());return value
                return fail
            return fn
        def fault(stage,rf,intended):
            hook(stage,rf,intended)
            if stage=='PREPARED' and case=='resource_write_failure':rf.close();note('close_before_replace')
            if stage=='PREPARED' and case=='partial_write_failure':
                rf.replace(intended[:max(1,len(intended)//2)]);note('actual_partial_write_then_exception');raise OSError('V04_PARTIAL')
            if stage=='WRITTEN' and case=='readback_failure':rf.close();note('close_before_readback')
            if stage=='WRITTEN' and case=='readback_mismatch':rf.replace(b'actual-wrong-bytes');note('actual_postwrite_substitution')
            if stage=='WRITTEN' and case=='runtime_after_write':note('after_actual_write');raise RuntimeError('V04_RUNTIME')
            if stage=='COMMITTED' and case=='runtime_after_commit':note('after_actual_commit');raise RuntimeError('V04_COMMITTED')
        def backend(*args):
            response=super(InstrumentedBroker,self).execute(*args)
            if case=='dispatch_return_failure':note('after_broker_return');raise RuntimeError('V04_DISPATCH_RETURN')
            return response
        Journal.prepare=prepare;Journal.close=close;win.api=api
        try:
            if self.config.get('v04_legacy_dispatch'):return backend(raw,principal,now,fault)
            from guardian.dispatch import dispatch
            return dispatch(SimpleNamespace(execute=backend),raw,principal,now,fault)
        finally:
            Journal.prepare=oldprepare;Journal.close=oldclose;win.api=oldapi
            worker.save(Path(self.config['root'])/'journal/fault.json',{'case':case,'events':events,'process':native.process(),'thread':native.thread()})

if __name__=='__main__':
    cfg=json.loads(Path(sys.argv[1]).read_bytes());worker.HardenedBroker=InstrumentedBroker
    try:{'server':worker.server,'client':worker.client,'probe':worker.probe}[cfg['role']](cfg)
    except Exception:
        import traceback
        worker.save(Path(cfg['root'])/'journal/fatal.json',{'control_broken':traceback.format_exc()});raise
