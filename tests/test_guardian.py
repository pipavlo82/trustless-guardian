import base64
import copy
import unittest

from guardian.policy import canonical,digest,evaluate,parse
from guardian.evidence import seal
from guardian.verifier import verify
from guardian.adapters import preserve_native_result
from tools.mutations import classify


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.p={'schema':'guardian.policy.v0','version':'v0','actors':['agent'],
          'action':'replace_utf8','resource':'sample','scope':'local','max_bytes':100,'max_ttl':30,'content_prefix':'approved:'}
        self.before=b'old';self.r={'schema':'guardian.action.v0','actor':'agent','action':'replace_utf8',
          'resource':'sample','scope':'local','policy_version':'v0','expires_at':1010,'nonce':'one',
          'content':'approved:new','evidence':{'before_sha256':digest(self.before)}}

    def decision(self,r=None,p=None):return evaluate(self.r if r is None else r,self.p if p is None else p,'agent',1000,digest(self.before),set())

    def record(self):
        after=self.r['content'].encode();pin=digest(canonical(self.p))
        return seal({'request':self.r,'policy':self.p,'request_sha256':digest(canonical(self.r)),
          'policy_sha256':pin,'principal':'agent','verification_time':1000,'used_nonces':[],
          'resource_identity':[1,2,3],'trusted_resource_identity':[1,2,3],
          'before_base64':base64.b64encode(self.before).decode(),'after_base64':base64.b64encode(after).decode(),
          'before_sha256':digest(self.before),'after_sha256':digest(after),'broker_result':'EXECUTED','decision':self.decision()})

    def test_exact_scope(self):
        d=self.decision();self.assertEqual(d['status'],'VERIFIED');self.assertEqual(d['scope']['content_sha256'],digest(b'approved:new'))

    def test_missing_is_not_refutation(self):
        self.assertEqual(self.decision({**self.r,'evidence':{}})['status'],'UNVERIFIABLE')

    def test_untrusted_authorization_flag(self):
        self.assertEqual(self.decision({**self.r,'authorized':True})['decision'],'DENY')

    def test_actor_context_not_caller_identity(self):
        self.assertEqual(evaluate(self.r,self.p,'someone_else',1000,digest(self.before),set())['reason'],'ACTOR')

    def test_replay(self):
        self.assertEqual(evaluate(self.r,self.p,'agent',1000,digest(self.before),{'one'})['reason'],'REPLAY')

    def test_expiry_bool_not_integer(self):self.assertEqual(self.decision({**self.r,'expires_at':True})['reason'],'EXPIRY')

    def test_duplicate_json(self):
        with self.assertRaises(ValueError):parse(b'{"a":1,"a":2}')

    def test_nonfinite_json(self):
        with self.assertRaises(ValueError):parse(b'{"a":NaN}')

    def test_policy_shape(self):self.assertEqual(self.decision(p={})['status'],'UNVERIFIABLE')

    def test_independent_record_oracle(self):
        r=self.record();self.assertTrue(verify(r,digest(canonical(self.p)),r['sha256'])['passed'])

    def test_resealed_false_scope(self):
        r=self.record();r['body']['decision']['scope']['resource']='arbitrary';r=seal(r['body'])
        self.assertFalse(verify(r,digest(canonical(self.p)),r['sha256'])['passed'])

    def test_tampered_bytes(self):
        r=self.record();r['body']['after_base64']=base64.b64encode(b'other').decode()
        self.assertFalse(verify(r,digest(canonical(self.p)),r['sha256'])['passed'])

    def test_native_result_preserved_not_authority(self):
        for native in (b'{"status":"VERIFIED"}',b'{"status":"REFUTED"}',b'{"status":"UNVERIFIABLE"}',b'{"status":"CANNOT_RECOMPUTE"}'):
            result=preserve_native_result('receiptos.verify.v2',native)
            self.assertEqual(bytes.fromhex(result['native_bytes_hex']),native)
            self.assertFalse(result['execution_authority']);self.assertEqual(result['guardian_authorization'],'UNVERIFIABLE')

    def test_crash_is_not_kill(self):
        good={'positive_ok':True,'negative_wrote':False}
        self.assertEqual(classify(good,None,good,True),'CRASHED')
        self.assertEqual(classify(good,good,good,True),'SURVIVED')
        self.assertEqual(classify(good,{'positive_ok':True,'negative_wrote':True},good,True),'KILLED')
        self.assertEqual(classify(None,None,good,True),'CONTROL_BROKEN')
        self.assertEqual(classify(good,good,good,False),'CONTROL_BROKEN')


if __name__=='__main__':unittest.main()
