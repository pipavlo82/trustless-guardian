"""Integrity records, not attestations of OS truth or bearer permissions."""
from .policy import canonical,digest


def seal(body,previous='0'*64):
    return {'schema':'guardian.evidence.v0','previous':previous,'body':body,
            'sha256':digest(canonical({'previous':previous,'body':body}))}
