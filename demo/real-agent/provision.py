"""Trusted provisioning only. Never invoked by an agent request."""


def protect_source(lab):
    lab.acl(lab.resource, broker='GRGW', agent='GRGX', other=None)  # V06 protected_acl
