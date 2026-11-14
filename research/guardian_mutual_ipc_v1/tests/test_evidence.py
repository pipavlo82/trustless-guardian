"""Synthetic tests for offline evidence admission, separate from actual native observations."""
import copy
import hashlib
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.guardian_mutual_ipc_v1 import protocol as p
from research.guardian_mutual_ipc_v1.verify_evidence import verify_case


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.trust={'schema':'guardian.broker-trust.v1','broker_id':'b','trust_root_version':'v1','key_id':'k',
                    'public_key':key.public_key().public_bytes_raw().hex(),'revoked':False,'not_before':900,'expires_at':2000}
        s=p.ClientSession(self.trust,'guardian-resonance-'+'a'*24,1000)
        hello=s.hello;answer={'verdict':'SYNTHETIC_OBSERVATIONS','nonce':'d'*64,'observations_scaled':[20,30,40],'scale':100,'tools_enabled':False}
        proposal={**s.context,'op':'PROPOSE_TOOL','nonce':'d'*64,'agent_id':'resonance-agent-v5','tool':'resonance.synthetic-hash-only.v0',
                  'resource_id':'resonance-synthetic-observation-v0','decision':'OBSERVE','ticks':3,'docker_errors':{'linux':5,'legacy':5}}
        hold={'verdict':'HOLD_GUARDIAN_GRANT_REQUIRED','grant_issued':False,'tool_executed':False}
        sid='S-1-15-2-synthetic';sh=hashlib.sha256(sid.encode()).hexdigest()
        self.r={'schema':'guardian.mutual-native-case.v1','case':'normal','status':'OBSERVED','production_ready':False,
                'grant_issued':False,'tool_executed':False,'global_runtime_acl_changed':False,'temporary_root_deleted':True,
                'trust':self.trust,'configured_trust':self.trust,'channel_id':s.context['channel_id'],'finished_at':1001,
                'expected_sid_sha256':sh,'client_exit':73,'client_token':{'appcontainer':True,'capability_count':0,'elevated':False,
                  'integrity_sid':'S-1-16-4096','appcontainer_sid':sid},
                'broker':{'client_identity':{'appcontainer':True,'capability_count':0,'sid_sha256':sh},'grant_issued':False,
                  'tool_executed':False,'production_ready':False,'client_result':{'op':'CLIENT_RESULT','code':73,'reason':hold['verdict']},
                  'transcript':[{'request':hello,'reply':p.sign_response(key,s.context,'hello',hello,answer,1000)},
                                {'request':proposal,'reply':p.sign_response(key,s.context,'result',proposal,hold,1000)}]}}
    def test_positive(self):self.assertEqual(verify_case('normal',self.r,self.trust),'HOLD_GUARDIAN_GRANT_REQUIRED')
    def test_evidence_tamper_controls(self):
        transforms=[lambda r:r.__setitem__('client_exit',0),lambda r:r.__setitem__('tool_executed',True),
                    lambda r:r.__setitem__('production_ready',True),lambda r:r.__setitem__('temporary_root_deleted',False),
                    lambda r:r['client_token'].__setitem__('capability_count',1),lambda r:r['client_token'].__setitem__('elevated',True),
                    lambda r:r['client_token'].__setitem__('integrity_sid','S-1-16-8192'),lambda r:r['client_token'].__setitem__('appcontainer',False),
                    lambda r:r['broker']['client_identity'].__setitem__('sid_sha256','0'*64),lambda r:r['broker'].__setitem__('grant_issued',True),
                    lambda r:r['broker']['transcript'][0]['reply'].__setitem__('signature','0'*128),
                    lambda r:r['broker']['transcript'][1]['request'].__setitem__('tool','shell'),
                    lambda r:r['broker']['transcript'].pop(),lambda r:r['broker']['transcript'].reverse()]
        for i,change in enumerate(transforms):
            r=copy.deepcopy(self.r);change(r)
            with self.subTest(index=i),self.assertRaises(ValueError):verify_case('normal',r,self.trust)
    def test_wrong_independent_root(self):
        t=dict(self.trust);t['key_id']='other'
        with self.assertRaises(ValueError):verify_case('normal',self.r,t)


if __name__=='__main__':unittest.main()
