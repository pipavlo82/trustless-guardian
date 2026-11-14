"""Offline trust admission. Caller selects policy, digest, clock and epoch floors.

This is not a production root distributor or a persistent anti-rollback store.
Historical validity never establishes current authorization or process identity.
"""
import hashlib
import json
import re

HEX = re.compile(r'[0-9a-f]{64}', re.ASCII)
NAME = re.compile(r'[a-zA-Z0-9._:-]{1,100}', re.ASCII)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    def check(v):
        if type(v) in (str, int, bool, type(None)): return
        if type(v) is list:
            for x in v: check(x)
            return
        if type(v) is dict and all(type(k) is str for k in v):
            for x in v.values(): check(x)
            return
        raise ValueError('CANONICAL_TYPE')
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def load(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, 'DUPLICATE_MEMBER')
            result[k] = v
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    require(raw in (canonical(value), canonical(value) + b'\n'), 'NONCANONICAL_EVIDENCE')
    return value


def root_at(root, at):
    fields = {'schema','broker_id','trust_root_version','key_id','public_key','revoked','not_before','expires_at'}
    require(type(root) is dict and set(root) == fields, 'TRUST_SHAPE')
    require(root['schema'] == 'guardian.broker-trust.v1', 'TRUST_SCHEMA')
    require(all(type(root[k]) is str and NAME.fullmatch(root[k]) for k in ('broker_id','trust_root_version','key_id')), 'TRUST_IDENTITY')
    require(type(root['public_key']) is str and HEX.fullmatch(root['public_key']), 'TRUST_KEY')
    require(root['revoked'] is False, 'TRUST_REVOKED')
    require(type(at) is int and type(root['not_before']) is int and type(root['expires_at']) is int and
            root['not_before'] <= at < root['expires_at'], 'TRUST_TIME')


def admit(policy, root, root_pin, *, now, minimum_policy_epoch, minimum_trust_epoch):
    fields = {'schema','mode','policy_epoch','trust_epoch','root_sha256','broker_id','key_id','trust_root_version',
              'authorized','revoked_at','issued_at','expires_at'}
    require(type(policy) is dict and set(policy) == fields, 'POLICY_SHAPE')
    require(policy['schema'] == 'guardian.mutual-replay-policy.v1' and policy['mode'] in ('historical','current'), 'POLICY_SCHEMA')
    require(all(type(x) is int and x > 0 for x in (minimum_policy_epoch, minimum_trust_epoch, policy['policy_epoch'],policy['trust_epoch'])), 'POLICY_EPOCH_TYPE')
    require(policy['policy_epoch'] >= minimum_policy_epoch, 'POLICY_ROLLBACK')
    require(policy['trust_epoch'] >= minimum_trust_epoch, 'TRUST_ROLLBACK')
    require(policy['authorized'] is True, 'TRUST_UNAUTHORIZED')
    require(type(now) is int and type(policy['issued_at']) is int and type(policy['expires_at']) is int and
            policy['issued_at'] <= now < policy['expires_at'], 'POLICY_TIME')
    require(policy['root_sha256'] == root_pin and type(root_pin) is str and HEX.fullmatch(root_pin), 'POLICY_ROOT_PIN')
    require(all(policy[k] == root[k] for k in ('broker_id','key_id','trust_root_version')), 'POLICY_ROOT_IDENTITY')
    require(policy['revoked_at'] is None or type(policy['revoked_at']) is int, 'REVOCATION_EVIDENCE')
    if policy['mode'] == 'current':
        root_at(root, now)
        require(policy['revoked_at'] is None or now < policy['revoked_at'], 'CURRENT_ROOT_REVOKED')
    return policy


def capture_authorized(policy, root, at):
    root_at(root, at)
    require(policy['revoked_at'] is None or at < policy['revoked_at'], 'CAPTURE_ROOT_REVOKED')
