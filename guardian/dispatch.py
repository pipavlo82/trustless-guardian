"""Execution-time exception boundary, not an authorization policy or transport."""

def dispatch(broker,raw,principal,now,hook=lambda *a:None):
    """Caller must authenticate first. A backend exception cannot prove no write.

    Preserve normal native broker decisions. Do not catch process termination or
    invent a response on missing transport output. Authentication is not authority.
    """
    try:return broker.execute(raw,principal,now,hook)
    except Exception:
        return {'status':'UNVERIFIABLE','decision':'DENY','scope':None,
                'reason':'DISPATCH_OUTCOME_UNCERTAIN','execution':'RECOVERY_REQUIRED',
                'retry_permitted':False,'failure_stage':'DISPATCH_UNKNOWN'}  # V04 dispatch_uncertainty
