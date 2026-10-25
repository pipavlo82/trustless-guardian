"""Research envelopes only. Native verification is never action permission."""
from .policy import digest

PINS={
 'receiptos.verify.v2':{'repository':'pipavlo82/receiptos-verify','commit':'f39ac3b289be6baef1140c53976d525d8eb45c8c',
   'interface':'src/core/verify-v2.mjs:verifyV2(requestInput,bundleInput)'},
 'veca.integration.v0':{'repository':'trustless-ai/verifiable-execution-claim-authorization','commit':'e2aca1a029203f1d5c73db2f8872b4240e793bfb',
   'interface':'src/integration/engine.py:evaluate(case),admit(presented,case)'}}


def preserve_native_result(profile,raw):
    if profile not in PINS:raise ValueError('unsupported adapter profile')
    if not isinstance(raw,bytes):raise TypeError('exact native output bytes required')
    return {'schema':'guardian.external-evidence.v0','source':PINS[profile],
      'profile':profile,'native_bytes_sha256':digest(raw),'native_bytes_hex':raw.hex(),
      'native_reverification':'NOT_IMPLEMENTED','guardian_authorization':'UNVERIFIABLE',
      'execution_authority':False,
      'missing_bindings':['trusted native inputs and verifier execution','actor','action','resource','scope','policy','expiry','nonce']}
