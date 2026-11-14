"""Frozen auditor witnesses; expected refusals precede the repair implementation.

Fixtures copied byte-for-byte from the 2026-11-13 adversarial audit. All are
synthetic; their published deterministic test key is not a production identity.
"""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.guardian_mutual_ipc_v1 import verify_evidence as v
from research.guardian_mutual_ipc_v1 import replay_policy as p

FIXTURES=Path(__file__).with_name('repair_fixtures')
NOW=1900000001
def fixture(name='positive'):return json.loads((FIXTURES/(name+'.json')).read_bytes())
def policy(root,**changes):
    x=dict(schema='guardian.mutual-replay-policy.v1',mode='historical',policy_epoch=7,trust_epoch=3,
        root_sha256=hashlib.sha256(p.canonical(root)).hexdigest(),authorized=True,revoked_at=None,issued_at=NOW-1,expires_at=NOW+1000,
        **{k:root[k] for k in ('broker_id','key_id','trust_root_version')})
    x.update(changes);return x
def admit(x,root,now=NOW):
    return p.admit(x,root,hashlib.sha256(p.canonical(root)).hexdigest(),now=now,minimum_policy_epoch=7,minimum_trust_epoch=3)
def resign(record):
    key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    for row in record['broker']['transcript']:
        row['reply']['payload']['request_sha256']=hashlib.sha256(p.canonical(row['request'])).hexdigest()
        row['reply']['signature']=key.sign(b'GUARDIAN-BROKER-AUTH-V1\x00'+p.canonical(row['reply']['payload'])).hex()

class RepairTests(unittest.TestCase):
    def test_frozen_positive(self):
        r=fixture();self.assertEqual(v.verify_case('normal',r,r['trust']),'HOLD_GUARDIAN_GRANT_REQUIRED')
    def test_frozen_revoked(self):
        r=fixture('revoked_root')
        with self.assertRaisesRegex(ValueError,'TRUST_REVOKED'):v.verify_case('normal',r,r['trust'])
    def test_frozen_expired(self):
        r=fixture('expired_root')
        with self.assertRaisesRegex(ValueError,'TRUST_TIME'):v.verify_case('normal',r,r['trust'])
    def test_frozen_nonce(self):
        r=fixture('malformed_nonce')
        with self.assertRaisesRegex(ValueError,'AUTH_POSITIVE'):v.verify_case('normal',r,r['trust'])
    def test_frozen_agent(self):
        r=fixture('wrong_agent')
        with self.assertRaisesRegex(ValueError,'HELLO_VERSION'):v.verify_case('normal',r,r['trust'])
    def test_historical_after_expiry_and_revocation(self):
        root=fixture()['trust'];x=policy(root,revoked_at=NOW+2)
        admit(x,root,now=NOW+200);p.capture_authorized(x,root,NOW)
        with self.assertRaisesRegex(ValueError,'CURRENT_ROOT_REVOKED'):admit(dict(x,mode='current'),root,now=NOW+3)
    def test_revoked_at_capture(self):
        root=fixture()['trust'];x=policy(root,revoked_at=NOW)
        admit(x,root)
        with self.assertRaisesRegex(ValueError,'CAPTURE_ROOT_REVOKED'):p.capture_authorized(x,root,NOW)
    def test_current_root_expiry(self):
        root=fixture()['trust'];x=policy(root,mode='current')
        with self.assertRaisesRegex(ValueError,'TRUST_TIME'):admit(x,root,now=NOW+200)
    def test_positive_policy(self):
        root=fixture()['trust'];admit(policy(root),root);admit(policy(root,mode='current'),root)
    def test_policy_refusals(self):
        root=fixture()['trust']
        for changes,reason in [({'authorized':False},'TRUST_UNAUTHORIZED'),({'authorized':1},'TRUST_UNAUTHORIZED'),
          ({'policy_epoch':6},'POLICY_ROLLBACK'),({'trust_epoch':2},'TRUST_ROLLBACK'),({'policy_epoch':True},'POLICY_EPOCH_TYPE'),
          ({'revoked_at':False},'REVOCATION_EVIDENCE'),({'root_sha256':'0'*64},'POLICY_ROOT_PIN'),({'broker_id':'substitute'},'POLICY_ROOT_IDENTITY'),
          ({'expires_at':NOW},'POLICY_TIME'),({'mode':'implicit'},'POLICY_SCHEMA')]:
            with self.subTest(changes=changes),self.assertRaisesRegex(ValueError,reason):admit(policy(root,**changes),root)
        for field in policy(root):
            x=policy(root);del x[field]
            with self.subTest(missing=field),self.assertRaisesRegex(ValueError,'POLICY_SHAPE'):admit(x,root)
    def test_strict_raw_admission(self):
        for raw in [b'{"x":1,"x":1}',b'{ "x":1}',b'{"x":1.0}',b'{"x":NaN}',b'{"x":1}\n\n']:
            with self.subTest(raw=raw),self.assertRaises(ValueError):p.load(raw)
        self.assertEqual(p.load(b'{"x":1}\n'),{'x':1})
    def test_signed_nonce_forms(self):
        for nonce in ['', 'F'*64,'f'*63,1,True,None,[],{}]:
            r=fixture();r['broker']['transcript'][0]['reply']['payload']['response']['nonce']=nonce
            r['broker']['transcript'][1]['request']['nonce']=nonce;resign(r)
            with self.subTest(nonce=nonce),self.assertRaises(ValueError):v.verify_case('normal',r,r['trust'])
    def test_signed_proposal_binding(self):
        for field,value in [('agent_id','substitute'),('resource_id','other'),('session_id','0'*64),('ticks',True),('op','OTHER'),('extra',1)]:
            r=fixture();r['broker']['transcript'][1]['request'][field]=value;resign(r)
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'PROPOSAL_BINDING'):v.verify_case('normal',r,r['trust'])
    def test_hello_shape(self):
        r=fixture();r['broker']['transcript'][0]['request']['extra']=1;resign(r)
        with self.assertRaisesRegex(ValueError,'HELLO_SHAPE'):v.verify_case('normal',r,r['trust'])
    def test_no_signature_whitespace(self):
        r=fixture();r['broker']['transcript'][0]['reply']['signature']+=' '
        with self.assertRaises(ValueError):v.verify_case('normal',r,r['trust'])

if __name__=='__main__':unittest.main()
