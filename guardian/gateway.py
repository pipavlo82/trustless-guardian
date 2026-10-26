"""Request admission; authenticated principal is supplied by the trusted launcher."""
from .policy import parse,evaluate


def receive(raw,policy,principal,now,before_sha256,used_nonces):
    if len(raw)>16384:raise ValueError('request too large')
    request=parse(raw)
    return request,evaluate(request,policy,principal,now,before_sha256,used_nonces)
