"""guardian.agent-tool.v1: a bounded proposal adapter, never an authority.

The broker independently authenticates the pipe caller and selects its policy.
This module has no filesystem resource access or policy decision implementation.
"""
import hashlib
import json
import re

VERSION = 'guardian.agent-tool.v1'
LIMIT = 16384
FIELDS = {'schema', 'actor', 'action', 'resource', 'scope', 'policy_version',
          'policy_sha256', 'expires_at', 'nonce', 'content', 'evidence'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    if not isinstance(raw, bytes) or len(raw) > LIMIT:
        raise ValueError('SIZE')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('DUPLICATE_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE')))


def translate(raw, context, now):
    value = decode(raw)
    if not isinstance(value, dict) or set(value) != FIELDS or value['schema'] != VERSION:
        raise ValueError('REQUEST_SCHEMA')
    policy = context['policy']  # provisioner-selected; never taken from the proposal
    pin = sha(canonical(policy))
    if pin != context['policy_sha256'] or value['policy_sha256'] != pin:
        raise ValueError('POLICY_PREIMAGE')
    expected = {'actor': context['agent_sid'], 'action': 'replace_utf8',
                'scope': policy['scope'], 'policy_version': policy['version'],
                'nonce': context['nonce'], 'evidence': {'before_sha256': context['before_sha256']}}
    if any(value[key] != expected[key] for key in expected):
        raise ValueError('CONTEXT_BINDING')
    if value['resource'] not in ('synthetic-source', 'protected-config'):
        raise ValueError('RESOURCE_IDENTIFIER')
    if not isinstance(value['content'], str) or len(value['content'].encode()) > 128:
        raise ValueError('CONTENT')
    if type(value['expires_at']) is not int or not now < value['expires_at'] <= now + 45:
        raise ValueError('EXPIRY')
    if not re.fullmatch('[a-f0-9]{64}', value['evidence']['before_sha256']):
        raise ValueError('EVIDENCE_DIGEST')
    request = {k: v for k, v in value.items() if k != 'policy_sha256'}
    request['schema'] = 'guardian.action.v0'
    return {'schema': 'guardian.ipc.v02', 'policy_sha256': pin, 'request': request}


def propose(arguments, context, now):
    if not isinstance(arguments, dict) or set(arguments) != {'resource', 'content'}:
        raise ValueError('TOOL_ARGUMENTS')
    p = context['policy']
    value = {'schema': VERSION, 'actor': context['agent_sid'], 'action': 'replace_utf8',
             'scope': p['scope'], 'policy_version': p['version'],
             'policy_sha256': context['policy_sha256'], 'expires_at': now + 45,
             'nonce': context['nonce'], 'evidence': {'before_sha256': context['before_sha256']}, **arguments}
    return value, translate(canonical(value), context, now)


def response(request, native):
    # Preserve native tri-state and execution ambiguity, never promote a receipt.
    if native.get('status') not in {'VERIFIED', 'REFUTED', 'UNVERIFIABLE'}:
        raise ValueError('NATIVE_STATUS')
    return {'schema': VERSION, 'stage': 'TOOL_RESULT', 'status': native['status'],
            'authorization': native.get('decision'), 'execution': native.get('execution'),
            'retry': 'PROHIBITED', 'native': native,
            'evidence_refs': {'tool_request_sha256': sha(canonical(request)),
                              'native_response_sha256': sha(canonical(native))}}
