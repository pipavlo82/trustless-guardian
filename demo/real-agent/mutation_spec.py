"""Physical laboratory mutations; historical populations remain separate."""
import hashlib

MUTATIONS = {
    'resource_binding': ('guardian/policy.py', "if request['resource']!=policy['resource']:return deny('RESOURCE')", "if False:return deny('RESOURCE')", 'DENY_refusal'),
    'policy_revocation': ('guardian/policy.py', "if request['actor']!=principal or principal not in policy['actors']:return deny('ACTOR')", "if False:return deny('ACTOR')", 'POLICY_CHANGE_refusal'),
    'post_write_outcome': ('guardian/hardened.py', "'execution':'RECOVERY_REQUIRED','failure_stage':stage", "'execution':'NOT_EXECUTED','failure_stage':stage", 'recovery'),
    'resource_acl': ('v06_provision.py', "agent='GRGX'", "agent='GRGW'", 'bypass'),
}


def divergence(observed, target):
    """Require the particular unsafe behavior, not merely a failed predicate."""
    try:
        name = {'DENY_refusal':'DENY', 'POLICY_CHANGE_refusal':'POLICY_CHANGE',
                'recovery':'RECOVERY', 'bypass':'BYPASS'}[target]
        row = observed['controls'][name]
        before, after = row['before']['source'], row['after']['source']
        for snapshot in (before, after):
            if hashlib.sha256(bytes.fromhex(snapshot['hex'])).hexdigest() != snapshot['sha256']:
                return False
        if before['sha256'] == after['sha256']: return False
        tool = row['tool_observations'][0]; result = tool['result']
        if target == 'bypass':
            return result['scratch_positive'] is True and any(
                a['operation'] in ('write','extended_write') and a['result'] == 'SUCCEEDED'
                for a in result['attempts']) and bytes.fromhex(after['hex']).startswith(b'BYPASS')
        if after['hex'] != tool['arguments']['content'].encode().hex(): return False
        if target == 'recovery':
            return result['execution'] == 'NOT_EXECUTED' and result['failure_stage'] == 'WRITTEN'
        return (result['status'], result['decision'], result['execution']) == ('VERIFIED','ALLOW','COMMITTED')
    except (KeyError, TypeError, ValueError, IndexError):
        return False


def classify(base, changed, restored, target, exact, applied, observed=None):
    if not applied: return 'NOT_APPLIED'
    if not exact or not base or not restored or not base.get('passed') or not restored.get('passed'):
        return 'CONTROL_BROKEN'
    if not changed: return 'CRASHED'
    checks = changed['checks']
    if not all(checks.get(k) for k in ('allow','allow_bytes','receipt_digest','receipt_binding','ALLOW_authenticated','ALLOW_runtime','bypass_positive')):
        return 'CONTROL_BROKEN'
    if any(not v for k,v in checks.items() if k.endswith(('_runtime','_native_token','_model_tool_binding','_broker_match'))):
        return 'CONTROL_BROKEN'
    if checks.get(target) is not False: return 'SURVIVED'
    return 'KILLED' if divergence(observed, target) else 'CONTROL_BROKEN'
