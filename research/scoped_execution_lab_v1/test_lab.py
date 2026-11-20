"""Independent expected outcomes: portable policy/negative controls + REAL Docker positive.
Synthetic broker structs below are unit fixtures, never native authentication evidence.
"""
import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.replay_challenge_v1.durable import DurableSecurityState
from research.scoped_execution_lab_v1 import lab

class LabTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='guardian-lab-tests-');self.root=Path(self.temp.name)
        self.sid='S-1-15-2-1-2-3-4-5-6-7';self.now=int(time.time())
        self.policy={'schema':'guardian.synthetic-policy.v1','enabled':True,'revoked':False,'sid':self.sid,'epoch':1,'not_before':self.now-1,'expires_at':self.now+90}
        self.result={'client_identity':{'appcontainer':True,'capability_count':0,'appcontainer_sid':self.sid},'verdict':'HOLD_GUARDIAN_GRANT_REQUIRED',
                     'client_result':{'op':'CLIENT_RESULT','code':73,'reason':'HOLD_GUARDIAN_GRANT_REQUIRED'},'transcript':[{'request':{}},{'request':{
                       'agent_id':'resonance-agent-v5','tool':'resonance.synthetic-hash-only.v0','resource_id':'resonance-synthetic-observation-v0','session_id':'a'*64}}]}
        self.request=lab.admit_live_result(self.result,self.sid,self.policy,self.now)
        self.key=Ed25519PrivateKey.generate();self.rkey=Ed25519PrivateKey.generate();self.grant=lab.issue(self.request,self.key,self.sid,self.now)
        self.state=DurableSecurityState(self.root/'state.sqlite',lab.SCOPE)
        self.calls=[];self.original=lab.docker
        def record(args,**kw):self.calls.append(args);return self.original(args,**kw)
        lab.docker=record
    def tearDown(self):
        lab.docker=self.original;self.state.close();self.temp.cleanup()
    def execute(self,request=None,grant=None,**kw):
        p=self.root/('job-'+str(len(list(self.root.iterdir()))))
        return lab.execute(self.request if request is None else request,self.grant if grant is None else grant,self.key.public_key(),self.rkey,self.state,self.policy,self.sid,self.now,p,**kw),p
    def denied(self,**kw):
        value,_=self.execute(**kw)
        self.assertEqual(value['status'],'REFUSED');self.assertEqual(value['launches'],0)
        self.assertFalse(any(x[0] in ('create','start') for x in self.calls),'unauthorized Docker creation')
    def signed_change(self,field,value):
        g=copy.deepcopy(self.grant);g['payload'][field]=value;g['signature']=base64.b64encode(self.key.sign(lab.canonical(g['payload']))).decode();return g
    def test_healthy_worker_and_node(self):
        value,p=self.execute();self.assertEqual(value['status'],'OBSERVED_SYNTHETIC_RESULT');self.assertTrue(value['cleanup'])
        q=subprocess.run(['node',str(lab.HERE/'verify.mjs'),str(p),str(p/'expectations.json')],capture_output=True,text=True,timeout=15)
        self.assertEqual(q.returncode,0,q.stdout+q.stderr);self.assertEqual(json.loads(q.stdout)['status'],'VERIFIED_UNDER_DECLARED_LAB_ASSUMPTIONS')
    def test_missing_grant(self):self.denied(grant={})
    def test_signature(self):
        g=copy.deepcopy(self.grant);g['signature']=base64.b64encode(b'\x00'*64).decode();self.denied(grant=g)
    def test_wrong_signer(self):
        g=copy.deepcopy(self.grant);g['signature']=base64.b64encode(Ed25519PrivateKey.generate().sign(lab.canonical(g['payload']))).decode();self.denied(grant=g)
    def test_request(self):
        req=copy.deepcopy(self.request);req['body']['proposal']['session_id']='b'*64;self.denied(request=req)
    def test_worker(self):self.denied(grant=self.signed_change('worker_sha256','0'*64))
    def test_image(self):self.denied(grant=self.signed_change('image_identity','sha256:'+'0'*64))
    def test_scope(self):self.denied(grant=self.signed_change('admission_scope','other'))
    def test_trust(self):self.denied(grant=self.signed_change('trust_version','old'))
    def test_subject(self):self.denied(grant=self.signed_change('subject','other'))
    def test_expired(self):self.now+=61;self.denied()
    def test_revoked_policy(self):
        self.policy['revoked']=True
        self.request['body']['policy_sha256']=lab.sha(lab.canonical(self.policy))
        self.grant=lab.issue(self.request,self.key,self.sid,self.now)
        self.denied()
    def test_missing_policy(self):self.policy={};self.denied()
    def test_policy_epoch(self):self.policy['epoch']=0;self.denied()
    def test_policy_binding(self):self.policy['expires_at']+=1;self.denied()
    def test_client_identity(self):
        self.result['client_identity']['appcontainer']=False
        with self.assertRaisesRegex(lab.SecurityError,'LAB_CLIENT_IDENTITY'):lab.admit_live_result(self.result,self.sid,self.policy,self.now)
    def test_client_capabilities(self):
        self.result['client_identity']['capability_count']=1
        with self.assertRaisesRegex(lab.SecurityError,'LAB_CLIENT_IDENTITY'):lab.admit_live_result(self.result,self.sid,self.policy,self.now)
    def test_client_sid(self):
        self.result['client_identity']['appcontainer_sid']='other'
        with self.assertRaisesRegex(lab.SecurityError,'LAB_CLIENT_IDENTITY'):lab.admit_live_result(self.result,self.sid,self.policy,self.now)
    def test_incomplete_ipc(self):
        self.result['client_result']={}
        with self.assertRaisesRegex(lab.SecurityError,'LAB_IPC_NOT_COMPLETE'):lab.admit_live_result(self.result,self.sid,self.policy,self.now)
    def test_tool_scope(self):
        self.result['transcript'][1]['request']['tool']='shell'
        with self.assertRaisesRegex(lab.SecurityError,'LAB_TOOL_SCOPE'):lab.admit_live_result(self.result,self.sid,self.policy,self.now)
    def test_replay(self):
        value,_=self.execute();self.assertEqual(value['status'],'OBSERVED_SYNTHETIC_RESULT');self.calls.clear();self.denied()
    def test_restart_replay(self):
        value,_=self.execute();self.assertEqual(value['status'],'OBSERVED_SYNTHETIC_RESULT');self.state.close();self.state=DurableSecurityState(self.root/'state.sqlite',lab.SCOPE);self.calls.clear();self.denied()
    def test_state_unavailable(self):self.state.close();self.denied()
    def test_output_tamper(self):
        value,p=self.execute();self.assertEqual(value['status'],'OBSERVED_SYNTHETIC_RESULT');(p/'stdout.bin').write_bytes(b'forged\n')
        q=subprocess.run(['node',str(lab.HERE/'verify.mjs'),str(p),str(p/'expectations.json')],capture_output=True,text=True)
        self.assertEqual(q.returncode,1);self.assertEqual(json.loads(q.stdout)['reason'],'OUTPUT_BINDING')
    def test_receipt_signature(self):
        value,p=self.execute();self.assertEqual(value['status'],'OBSERVED_SYNTHETIC_RESULT')
        r=json.loads((p/'receipt.json').read_bytes());r['signature']=base64.b64encode(b'\x00'*64).decode();(p/'receipt.json').write_bytes(lab.canonical(r)+b'\n')
        q=subprocess.run(['node',str(lab.HERE/'verify.mjs'),str(p),str(p/'expectations.json')],capture_output=True,text=True)
        self.assertEqual(q.returncode,1);self.assertEqual(json.loads(q.stdout)['reason'],'SIGNATURE')
    def test_signed_wrong_result(self):
        value,p=self.execute();self.assertEqual(value['status'],'OBSERVED_SYNTHETIC_RESULT')
        # Trusted test signer signs a self-consistent but false output. Recompute must disagree.
        fake=lab.canonical({'action':'synthetic_request_hash','request_file_sha256':'0'*64,'uid':65534})+b'\n'
        (p/'stdout.bin').write_bytes(fake)
        o=json.loads((p/'outcome.json').read_bytes());o['stdout_sha256']=lab.sha(fake);(p/'outcome.json').write_bytes(lab.canonical(o)+b'\n')
        r=json.loads((p/'receipt.json').read_bytes());rp=r['payload'];rp['stdout_sha256']=lab.sha(fake);rp['outcome_sha256']=lab.sha(lab.canonical(o))
        observed={k:rp[k] for k in ('container_started','exit_code','timed_out','launch_error','outcome_sha256','stdout_sha256','stderr_sha256')}
        rp['evidence_sha256']=lab.sha(lab.canonical(observed));r['signature']=base64.b64encode(self.rkey.sign(lab.canonical(rp))).decode();(p/'receipt.json').write_bytes(lab.canonical(r)+b'\n')
        q=subprocess.run(['node',str(lab.HERE/'verify.mjs'),str(p),str(p/'expectations.json')],capture_output=True,text=True)
        self.assertEqual(q.returncode,1);self.assertEqual(json.loads(q.stdout)['reason'],'SYNTHETIC_RECOMPUTE')
    def test_outcome_contradiction(self):
        value,p=self.execute();self.assertEqual(value['status'],'OBSERVED_SYNTHETIC_RESULT')
        o=json.loads((p/'outcome.json').read_bytes());o['exit_code']=42;(p/'outcome.json').write_bytes(lab.canonical(o)+b'\n')
        r=json.loads((p/'receipt.json').read_bytes());rp=r['payload'];rp['outcome_sha256']=lab.sha(lab.canonical(o))
        observed={k:rp[k] for k in ('container_started','exit_code','timed_out','launch_error','outcome_sha256','stdout_sha256','stderr_sha256')}
        rp['evidence_sha256']=lab.sha(lab.canonical(observed));r['signature']=base64.b64encode(self.rkey.sign(lab.canonical(rp))).decode();(p/'receipt.json').write_bytes(lab.canonical(r)+b'\n')
        q=subprocess.run(['node',str(lab.HERE/'verify.mjs'),str(p),str(p/'expectations.json')],capture_output=True,text=True)
        self.assertEqual(q.returncode,1);self.assertEqual(json.loads(q.stdout)['reason'],'OUTCOME_CONTRADICTION')
    def test_timeout_cleanup(self):
        # Deadline zero exercises actual cancellation even if worker might already finish.
        value,p=self.execute(deadline=0)
        self.assertEqual(value['status'],'UNKNOWN');self.assertTrue(value['timed_out']);self.assertTrue(value['cleanup'])
        self.assertEqual(value['lifecycle'],'RECOVERY_REQUIRED')
    def test_inspect_isolation(self):
        def bad(args,**kw):
            v=self.original(args,**kw)
            if args[0]=='inspect' and v.returncode==0:
                x=json.loads(v.stdout);x[0]['HostConfig']['Privileged']=True;v.stdout=json.dumps(x).encode()
            return v
        lab.docker=bad
        value,_=self.execute();self.assertEqual(value['status'],'UNKNOWN');self.assertEqual(value['reason'],'WORKER_ISOLATION');self.assertEqual(value['launches'],0);self.assertTrue(value['cleanup'])

if __name__=='__main__':unittest.main(verbosity=2)
