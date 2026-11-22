"""Challenge authentication to scoped execution-grant issuance."""

from research.auth_gateway_v1.errors import SecurityError
from research.auth_gateway_v1.jwt_auth import authenticate_jwt
from research.auth_gateway_v1.mcp_auth import authenticate_mcp
from research.auth_gateway_v1.model import RequestBinding
from research.auth_gateway_v1.policy import authorize

from .challenge import authenticate_challenged_siwe
from .scoped_grant import issue_scoped_execution_grant


class GuardianChallengeGateway:
    def __init__(
        self,
        trust,
        jwt_nonces,
        durable_state,
        grant_private_key,
        admission_scope,
        worker_sha256,
        image_identity,
        challenge_domain="guardian.local",
        challenge_uri="https://guardian.local/auth",
        challenge_chain_id=31337,
    ):
        if durable_state.scope != admission_scope:
            raise SecurityError("DURABLE_SCOPE_MISMATCH")
        self.trust = trust
        self.jwt_nonces = jwt_nonces
        self.durable_state = durable_state
        self.grant_private_key = grant_private_key
        self.admission_scope = admission_scope
        self.worker_sha256 = worker_sha256
        self.image_identity = image_identity
        self.challenge_domain = challenge_domain
        self.challenge_uri = challenge_uri
        self.challenge_chain_id = challenge_chain_id

    def issue_challenge(self, request, wallet_address, session_id, now):
        self.trust.validate(now)
        binding = RequestBinding.from_request(request)
        wallet = self.trust.active_wallet(wallet_address, now)
        if binding.agent_id not in wallet.agent_ids or binding.resource_id not in wallet.resource_ids:
            raise SecurityError("SIWE_WALLET_RESOURCE")
        return self.durable_state.issue_challenge(
            session_id=session_id,
            domain=self.challenge_domain,
            uri=self.challenge_uri,
            wallet=wallet.address,
            chain_id=self.challenge_chain_id,
            request_id=binding.request_id,
            binding_sha256=binding.digest(),
            now=now,
        )

    def authenticate(
        self,
        jwt_token,
        challenge_id,
        session_id,
        siwe_message,
        siwe_signature,
        mcp_header,
        request,
        now,
    ):
        binding = RequestBinding.from_request(request)
        jwt_principal = authenticate_jwt(
            jwt_token,
            binding,
            self.trust,
            self.jwt_nonces,
            now,
        )
        siwe_principal = authenticate_challenged_siwe(
            siwe_message,
            siwe_signature,
            challenge_id,
            session_id,
            binding,
            jwt_principal.wallet,
            self.trust,
            self.durable_state,
            now,
            self.challenge_domain,
            self.challenge_uri,
            self.challenge_chain_id,
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
        challenge_id,
        session_id,
        siwe_message,
        siwe_signature,
        mcp_header,
        request,
        now,
        grant_id,
    ):
        binding, jwt_principal, siwe_principal, mcp_principal = self.authenticate(
            jwt_token,
            challenge_id,
            session_id,
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
        grant = issue_scoped_execution_grant(
            self.grant_private_key,
            binding,
            jwt_principal,
            self.trust.version,
            self.admission_scope,
            self.worker_sha256,
            self.image_identity,
            now,
            grant_id,
        )
        return {
            "sequence": ["SERVER_CHALLENGE", "AUTHENTICATE", "AUTHORIZE", "DURABLE_ADMISSION_PENDING"],
            "binding_sha256": binding.digest(),
            "authorization": {"verdict": decision.verdict, "reason": decision.reason},
            "auth_sources": [
                jwt_principal.source,
                siwe_principal.source,
                "MCP_BEARER_SCOPED",
            ],
            "grant": grant,
        }
