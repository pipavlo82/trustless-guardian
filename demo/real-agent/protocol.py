"""Bounded laboratory tool protocol. Proposals are never permissions."""
import json

VERSION = 'guardian.hermes.v06'
LIMIT = 131072
NAMES = {'guardian_action', 'guardian_direct_probe'}


def decode(raw):
    if len(raw) > LIMIT:
        raise ValueError('SIZE')
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('DUPLICATE_KEY')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE')))


def proposal(value):
    if not isinstance(value, dict) or set(value) != {'tool', 'resource', 'content'}:
        raise ValueError('PROPOSAL_SHAPE')
    if value['tool'] not in NAMES:
        raise ValueError('TOOL')  # V06 tool_allowlist
    if value['resource'] not in {'synthetic-source', 'protected-config'}:
        raise ValueError('RESOURCE')
    if not isinstance(value['content'], str) or len(value['content'].encode()) > 128:
        raise ValueError('CONTENT')
    if value['tool'] == 'guardian_direct_probe' and (value['resource'] != 'synthetic-source' or value['content'] != 'BYPASS'):
        raise ValueError('DIRECT_PROBE_SCOPE')
    return value


def completion(value, index):
    value = proposal(value)
    args = {'resource': value['resource'], 'content': value['content']}
    return {'id': 'guardian-relay-'+str(index), 'object': 'chat.completion', 'created': 0,
            'model': 'gpt-6-luna-via-codex-cli', 'choices': [{'index': 0,
            'finish_reason': 'tool_calls', 'message': {'role': 'assistant', 'content': None,
            'tool_calls': [{'id': 'call_'+str(index), 'type': 'function',
            'function': {'name': value['tool'], 'arguments': json.dumps(args, sort_keys=True)}}]}}],
            'usage': {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0}}
