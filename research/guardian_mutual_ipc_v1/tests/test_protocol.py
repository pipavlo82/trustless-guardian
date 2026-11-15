import copy
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.guardian_mutual_ipc_v1 import protocol as p


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))  # public synthetic test fixture, not a deployment key
        self.trust = {"schema": "guardian.broker-trust.v1", "broker_id": "broker-test", "trust_root_version": "root-v1",
                      "key_id": "key-v1", "public_key": self.key.public_key().public_bytes_raw().hex(),
                      "revoked": False, "not_before": 900, "expires_at": 2000}
        self.clock = [0]
        self.s = p.ClientSession(self.trust, "guardian-resonance-" + "a"*24, 1000,
                                 session_id="b"*64, challenge="c"*64, clock=lambda: self.clock[0])
        self.response = {"verdict": "SYNTHETIC_OBSERVATIONS", "nonce": "d"*64,
                         "observations_scaled": [20,30,40], "scale": 100, "tools_enabled": False}
        self.envelope = p.sign_response(self.key, self.s.context, "hello", self.s.hello, self.response, 1000)

    def accept(self, envelope=None):
        return self.s.accept(envelope or self.envelope, "hello", self.s.hello, 1001)

    def changed(self, field, value):
        e = copy.deepcopy(self.envelope); e['payload'][field] = value
        e['signature'] = self.key.sign(p.DOMAIN + p.encode(e['payload'])).hex()
        return e

    def test_positive(self): self.assertEqual(self.accept(), self.response)
    def test_hold_only(self):
        self.accept(); request={'op':'synthetic','n':1}
        reply={'verdict':'HOLD_GUARDIAN_GRANT_REQUIRED','grant_issued':False,'tool_executed':False}
        e=p.sign_response(self.key,self.s.context,'result',request,reply,1000)
        self.assertEqual(self.s.accept(e,'result',request,1001),reply)
    def test_missing_auth(self):
        with self.assertRaisesRegex(p.Refused,'AUTH_MISSING'):self.accept(self.response)
    def test_signature(self):
        e=copy.deepcopy(self.envelope);e['signature']='00'*64
        with self.assertRaisesRegex(p.Refused,'AUTH_SIGNATURE'):self.accept(e)
    def test_wrong_key(self):
        e=copy.deepcopy(self.envelope);e['signature']=Ed25519PrivateKey.generate().sign(p.DOMAIN+p.encode(e['payload'])).hex()
        with self.assertRaisesRegex(p.Refused,'AUTH_SIGNATURE'):self.accept(e)
    def test_wrong_session(self):
        with self.assertRaisesRegex(p.Refused,'AUTH_SESSION'):self.accept(self.changed('session_id','0'*64))
    def test_wrong_challenge(self):
        with self.assertRaisesRegex(p.Refused,'AUTH_CHALLENGE'):self.accept(self.changed('client_challenge','0'*64))
    def test_wrong_channel(self):
        with self.assertRaisesRegex(p.Refused,'AUTH_CHANNEL'):self.accept(self.changed('channel_id','other'))
    def test_wrong_request(self):
        with self.assertRaisesRegex(p.Refused,'AUTH_REQUEST'):self.accept(self.changed('request_sha256','0'*64))
    def test_wrong_broker(self):
        with self.assertRaisesRegex(p.Refused,'AUTH_AUTHORITY'):self.accept(self.changed('broker_id','other'))
    def test_wrong_root(self):
        with self.assertRaisesRegex(p.Refused,'AUTH_AUTHORITY'):self.accept(self.changed('trust_root_version','other'))
    def test_wrong_key_id(self):
        with self.assertRaisesRegex(p.Refused,'AUTH_AUTHORITY'):self.accept(self.changed('key_id','other'))
    def test_wrong_version(self):
        with self.assertRaisesRegex(p.Refused,'AUTH_VERSION'):self.accept(self.changed('protocol','other'))
    def test_wrong_phase(self):
        with self.assertRaisesRegex(p.Refused,'AUTH_PHASE'):self.accept(self.changed('phase','result'))
    def test_expired_reply(self):
        self.envelope=p.sign_response(self.key,self.s.context,'hello',self.s.hello,self.response,900)
        with self.assertRaisesRegex(p.Refused,'AUTH_TIME'):self.accept()
    def test_future_reply(self):
        self.envelope=p.sign_response(self.key,self.s.context,'hello',self.s.hello,self.response,1100)
        with self.assertRaisesRegex(p.Refused,'AUTH_TIME'):self.accept()
    def test_deadline(self):
        self.clock[0]=31
        with self.assertRaisesRegex(p.Refused,'AUTH_DEADLINE'):self.accept()
    def test_replay(self):
        self.accept()
        with self.assertRaisesRegex(p.Refused,'AUTH_REPLAY_OR_ORDER'):self.accept()
    def test_refusal_consumes(self):
        with self.assertRaises(p.Refused):self.accept(self.changed('session_id','0'*64))
        with self.assertRaisesRegex(p.Refused,'AUTH_REPLAY_OR_ORDER'):self.accept()
    def test_missing_trust(self):
        with self.assertRaisesRegex(p.Refused,'TRUST_MISSING'):p.validate_trust({},1000)
    def test_revoked_trust(self):
        self.trust['revoked']=True
        with self.assertRaisesRegex(p.Refused,'TRUST_REVOKED'):p.validate_trust(self.trust,1000)
    def test_missing_key(self):
        del self.trust['public_key']
        with self.assertRaisesRegex(p.Refused,'TRUST_MISSING'):p.validate_trust(self.trust,1000)
    def test_malformed_key(self):
        self.trust['public_key']='x'
        with self.assertRaisesRegex(p.Refused,'TRUST_KEY'):p.validate_trust(self.trust,1000)
    def test_expired_trust(self):
        with self.assertRaisesRegex(p.Refused,'TRUST_TIME'):p.validate_trust(self.trust,2000)
    def test_strict_boolean(self):
        self.trust['revoked']=0
        with self.assertRaisesRegex(p.Refused,'TRUST_REVOKED'):p.validate_trust(self.trust,1000)
    def test_no_execution_promotion(self):
        self.accept(); request={'x':1};reply={'verdict':'HOLD_GUARDIAN_GRANT_REQUIRED','grant_issued':False,'tool_executed':True}
        e=p.sign_response(self.key,self.s.context,'result',request,reply,1000)
        with self.assertRaisesRegex(p.Refused,'RESPONSE_NOT_HOLD'):self.s.accept(e,'result',request,1001)
    def test_changed_body(self):
        e=copy.deepcopy(self.envelope);e['payload']['response']['nonce']='f'*64
        with self.assertRaisesRegex(p.Refused,'AUTH_SIGNATURE'):self.accept(e)
    def test_final_signature(self):
        self.accept();request={'x':1};reply={'verdict':'HOLD_GUARDIAN_GRANT_REQUIRED','grant_issued':False,'tool_executed':False}
        e=p.sign_response(self.key,self.s.context,'result',request,reply,1000);e['signature']='00'*64
        with self.assertRaisesRegex(p.Refused,'AUTH_SIGNATURE'):self.s.accept(e,'result',request,1001)
    def test_strict_frames(self):
        for raw in [b'{"a":1,"a":2}',b'{ "a":1}',b'{"a":1.0}',b'[] '+b'x'*4096,b'NaN']:
            with self.subTest(raw=raw[:12]),self.assertRaises(p.Refused):p.decode(raw)
    def test_generated_challenges(self):
        other=p.ClientSession(self.trust,self.s.context['channel_id'],1000)
        self.assertNotEqual(other.context['client_challenge'],self.s.context['client_challenge'])
        with self.assertRaisesRegex(p.Refused,'AUTH_SESSION'):other.accept(self.envelope,'hello',other.hello,1001)


if __name__=='__main__':unittest.main()
