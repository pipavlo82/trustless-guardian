"""Opt-in gate inside RC3 execution/reconciliation. No new authorization path.

Production provider intentionally cannot return CURRENT until an independently
verified finalized latest-head implementation exists. Lab challenges are explicit.
Configuration belongs to the trusted supervisor, never to request/evidence bytes.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading

_active = threading.local()


class CheckpointHold(Exception):
    pass


class ExternalCheckpointGate:
    def __init__(self, root):
        self.root = Path(root).resolve()
        try:
            path = Path(os.environ['GUARDIAN_CHECKPOINT_CONFIG']).resolve()
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != os.environ['GUARDIAN_CHECKPOINT_CONFIG_SHA256']:
                raise CheckpointHold('HOLD_HEAD_MISMATCH:CONFIG_PIN')
            self.config = json.loads(raw)
            if set(self.config) != {'schema','state_root','lock_path','provider','trust_policy','trust_policy_sha256','chain_path'}:
                raise CheckpointHold('HOLD_HEAD_MISMATCH:CONFIG_FIELDS')
            if self.config['schema'] != 'guardian.external-checkpoint-config.v1':
                raise CheckpointHold('HOLD_HEAD_MISMATCH:CONFIG_SCHEMA')
            if Path(self.config['state_root']).resolve() != self.root:
                raise CheckpointHold('HOLD_HEAD_MISMATCH:STATE_ROOT')
            self.config_raw = raw
            self.config_path = path
            self.snapshot = None
        except CheckpointHold:
            raise
        except Exception as exc:
            raise CheckpointHold('LATEST_HEAD_NOT_ESTABLISHED:CONFIG_UNAVAILABLE') from exc

    @contextlib.contextmanager
    def serialize(self):
        # Separate pinned lock path: rollback of the state directory is not a lock reset.
        lock_path = Path(self.config['lock_path']).resolve()
        try: handle = lock_path.open('a+b')
        except OSError as exc: raise CheckpointHold('HOLD_REMOTE_UNAVAILABLE:LOCK') from exc
        try:
            if handle.tell() == 0:
                handle.write(b'\0'); handle.flush()
            handle.seek(0)
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise CheckpointHold('RECOVERY_REQUIRED:CONCURRENT_OPERATION') from exc
            _active.gate = self
            yield
        finally:
            _active.gate = None
            try:
                if self.snapshot is not None: self.snapshot.cleanup()
            finally:
                handle.close()  # OS releases the lock after normal exit or process death.

    def require_current(self, operation):
        cfg = self.config
        if self.config_path.read_bytes() != self.config_raw:
            raise CheckpointHold('HOLD_HEAD_MISMATCH:CONFIG_CHANGED')
        # A profile spelling "finalized" or two RPC replies is not finality proof.
        if cfg['provider'] != 'synthetic_challenge':
            raise CheckpointHold('LATEST_HEAD_NOT_ESTABLISHED:FINALIZED_PROVIDER_NOT_IMPLEMENTED')
        if os.environ.get('GUARDIAN_CHECKPOINT_LAB_ONLY') != '1':
            raise CheckpointHold('LATEST_HEAD_NOT_ESTABLISHED:SYNTHETIC_PROVIDER')
        try:
            from . import checkpoint_verify as verify
            policy_raw = Path(cfg['trust_policy']).read_bytes()
            if hashlib.sha256(policy_raw).hexdigest() != cfg['trust_policy_sha256']:
                raise CheckpointHold('HOLD_HEAD_MISMATCH:TRUST_PIN')
            policy = verify.parse(policy_raw)
            if self.snapshot is None:
                self.snapshot = tempfile.TemporaryDirectory(prefix='guardian-checkpoint-gate-')
                scratch = Path(self.snapshot.name).resolve()
                if not scratch.is_relative_to(Path(tempfile.gettempdir()).resolve()):
                    raise CheckpointHold('HOLD_HEAD_MISMATCH:SCRATCH_SCOPE')
                case = scratch / 'case'; state = case / 'state'; state.mkdir(parents=True)
                for name in ('policy.json',): shutil.copy2(self.root/name, state/name)
                for source in self.root.glob('state.sqlite*'): shutil.copy2(source, state/source.name)
                shutil.copytree(self.root/'job', state/'job')
                shutil.copy2(cfg['chain_path'], case/'chain.json')
                self.case = case
            # Recheck fresh remote head against the immutable admitted snapshot while
            # this process owns the operation lock. Own lifecycle transitions may advance.
            scratch = Path(self.snapshot.name)
            sql = Path(tempfile.mkdtemp(prefix='read-', dir=scratch))/'sql'
            result = verify.verify(self.case, policy, sql, lab=True)
            status = result['status']
            if status != 'CURRENT':
                reason = result.get('reason', status)
                if status == 'HOLD_LOCAL_ROLLBACK': raise CheckpointHold(status)
                if 'HTTPError' in reason or 'URLError' in reason or 'Timeout' in reason:
                    raise CheckpointHold('HOLD_REMOTE_UNAVAILABLE')
                if 'REMOTE_FRESHNESS' in reason or 'REMOTE_BELOW_HIGH_WATER' in reason:
                    raise CheckpointHold('LATEST_HEAD_NOT_ESTABLISHED:'+reason)
                raise CheckpointHold('HOLD_HEAD_MISMATCH:'+reason)
            return {'status':'CURRENT','scope':'SYNTHETIC_REMOTE_ONLY','operation':operation}
        except CheckpointHold:
            raise
        except Exception as exc:
            raise CheckpointHold('HOLD_HEAD_MISMATCH:'+type(exc).__name__) from exc


def protected(operation, root_selector):
    """All normal RC3 calls reach this wrapper, including direct Python/CLI calls.
    Trusted-host Python introspection, legacy executors and raw Docker are not sandboxed here.
    """
    def decorate(function):
        def entry(*args, **kwargs):
            required = os.environ.get('GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED')
            if required is None:
                return function(*args, **kwargs)  # explicit compatibility, unchanged semantics
            try:
                if required != '1': raise CheckpointHold('LATEST_HEAD_NOT_ESTABLISHED:INVALID_REQUIRED_MODE')
                gate = ExternalCheckpointGate(root_selector(args, kwargs))
                with gate.serialize():
                    gate.require_current(operation)
                    return function(*args, **kwargs)
            except CheckpointHold as exc:
                return {'status':'HOLD','reason':str(exc),'launches':0,'dispatches':0,
                        'retry_permitted':False,'checkpoint_gate':'ENFORCED'}
        entry.__name__ = function.__name__
        entry.__doc__ = function.__doc__
        return entry
    return decorate


def recheck_current(operation):
    if os.environ.get('GUARDIAN_EXTERNAL_CHECKPOINT_REQUIRED') is None:
        return
    gate = getattr(_active, 'gate', None)
    if gate is None: raise CheckpointHold('LATEST_HEAD_NOT_ESTABLISHED:NO_OPERATION_LEASE')
    gate.require_current(operation)
