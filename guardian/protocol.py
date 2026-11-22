"""Portable exact envelope contract; it confers no execution authority."""
from .policy import parse

LIMIT = 16384


def envelope(raw, expected_pin):
    if not isinstance(raw,bytes) or len(raw) > LIMIT: raise ValueError('SIZE')
    value = parse(raw)
    if not isinstance(value,dict) or set(value) != {'schema','policy_sha256','request'}:
        raise ValueError('ENVELOPE')
    if value['schema'] != 'guardian.ipc.v02': raise ValueError('PROTOCOL')
    if value['policy_sha256'] != expected_pin: raise ValueError('POLICY_BINDING')  # V02 envelope_pin
    return value['request']
