"""Physical laboratory mutations; historical populations remain separate."""
MUTATIONS = {
    'resource_binding': ('guardian/policy.py', "if request['resource']!=policy['resource']:return deny('RESOURCE')", "if False:return deny('RESOURCE')", 'DENY_refusal'),
    'policy_revocation': ('guardian/policy.py', "if request['actor']!=principal or principal not in policy['actors']:return deny('ACTOR')", "if False:return deny('ACTOR')", 'POLICY_CHANGE_refusal'),
    'post_write_outcome': ('guardian/hardened.py', "'execution':'RECOVERY_REQUIRED','failure_stage':stage", "'execution':'NOT_EXECUTED','failure_stage':stage", 'recovery'),
    'resource_acl': ('v06_provision.py', "agent='GRGX'", "agent='GRGW'", 'bypass'),
}


def classify(base, changed, restored, target, exact, applied):
    if not applied: return 'NOT_APPLIED'
    if not exact or not base or not restored or not base.get('passed') or not restored.get('passed'):
        return 'CONTROL_BROKEN'
    if not changed: return 'CRASHED'
    checks = changed['checks']
    if not all(checks.get(k) for k in ('allow','allow_bytes','receipt_digest','receipt_binding','ALLOW_authenticated','ALLOW_runtime','bypass_positive')):
        return 'CONTROL_BROKEN'
    if any(not v for k,v in checks.items() if k.endswith(('_runtime','_native_token','_model_tool_binding','_broker_match'))):
        return 'CONTROL_BROKEN'
    return 'KILLED' if checks.get(target) is False else 'SURVIVED'
