"""Proposal-only tool contract. NOT a native Codex/ReceiptOS/VECA adapter.

The trusted provisioner selects context. Authentication is still performed by
the broker from the actual pipe token. Encoding an envelope grants no authority.
"""
import json

FIELDS = {'resource', 'content', 'nonce', 'expires_at', 'before_sha256'}


def proposal(value, *, actor, policy, policy_sha256):
    if not isinstance(value, dict) or set(value) != FIELDS: raise ValueError('TOOL_FIELDS')
    if value['resource'] != policy['resource']: raise ValueError('TOOL_RESOURCE')
    request = {'schema': 'guardian.action.v0', 'actor': actor, 'action': policy['action'],
               'resource': value['resource'], 'scope': policy['scope'], 'policy_version': policy['version'],
               'content': value['content'], 'nonce': value['nonce'], 'expires_at': value['expires_at'],
               'evidence': {'before_sha256': value['before_sha256']}}
    # Full value/schema/time/evidence validation belongs to the native broker.
    envelope = {'schema': 'guardian.ipc.v02', 'policy_sha256': policy_sha256, 'request': request}
    return json.dumps(envelope, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
