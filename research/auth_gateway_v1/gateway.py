"""AUTHENTICATE -> AUTHORIZE -> issue a confined-execution grant."""

from .errors import SecurityError
from .grant import issue_execution_grant
from .jwt_auth import authenticate_jwt
from .mcp_auth import authenticate_mcp
from .model import RequestBinding
from .policy import authorize
from .siwe_auth import authenticate_siwe


class GuardianAuthGateway:
    def __init__(self, trust, jwt_nonces, siwe_nonces, grant_private_key):
        self.trust = trust
        self.jwt_nonces = jwt_nonces
        self.siwe_nonces = siwe_nonces
        self.grant_private_key = grant_private_key

    def authenticate(self, jwt_token, siwe_message, siwe_signature, mcp_header, request, now):
        binding = RequestBinding.from_request(request)
        jwt_principal = authenticate_jwt(jwt_token, binding, self.trust, self.jwt_nonces, now)
        siwe_principal = authenticate_siwe(
            siwe_message,
            siwe_signature,
            binding,
            self.trust,
            self.siwe_nonces,
            now,
        )
        mcp_principal = authenticate_mcp(
            mcp_header,
            binding,
            self.trust,
            jwt_principal.subject,
            now,
        )
        return binding, jwt_principal, siwe_principal, mcp_principal

    def authorize_and_issue(
        self,
        jwt_token,
        siwe_message,
        siwe_signature,
        mcp_header,
        request,
        now,
        grant_id,
    ):
        binding, jwt_principal, siwe_principal, mcp_principal = self.authenticate(
            jwt_token,
            siwe_message,
            siwe_signature,
            mcp_header,
            request,
            now,
        )
        decision = authorize(
            jwt_principal,
            siwe_principal,
            mcp_principal,
            binding,
            self.trust,
            now,
        )
        if not decision.allowed:
            raise SecurityError(decision.reason)
        grant = issue_execution_grant(
            self.grant_private_key,
            binding,
            jwt_principal,
            self.trust.version,
            now,
            grant_id,
        )
        return {
            "sequence": ["AUTHENTICATE", "AUTHORIZE", "CONFINED_EXECUTION_PENDING"],
            "binding_sha256": binding.digest(),
            "authorization": {"verdict": decision.verdict, "reason": decision.reason},
            "auth_sources": [jwt_principal.source, siwe_principal.source, "MCP_BEARER_SCOPED"],
            "grant": grant,
        }
