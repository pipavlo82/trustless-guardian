import copy
from dataclasses import replace
from datetime import datetime, timezone
import json
import secrets
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from eth_account import Account
import jwt

from research.auth_gateway_v1.errors import SecurityError
from research.auth_gateway_v1.gateway import GuardianAuthGateway
from research.auth_gateway_v1.grant import verify_execution_grant
from research.auth_gateway_v1.model import RequestBinding
from research.auth_gateway_v1.nonce import BoundedNonceStore
from research.auth_gateway_v1.siwe_auth import authenticate_siwe
from research.auth_gateway_v1.trust import JwtKeyRecord
from tests_auth_v1.fixtures import Fixture, _public_pem


class AuthGatewayTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.gateway = GuardianAuthGateway(
            self.f.trust,
            self.f.jwt_nonces,
            self.f.siwe_nonces,
            self.f.grant_key,
        )

    def issue(self, jwt_token=None, siwe=None, signature=None, mcp=None, request=None, grant_id=None):
        if jwt_token is None:
            jwt_token = self.f.make_jwt()
        if siwe is None:
            siwe, signature = self.f.make_siwe()
        return self.gateway.authorize_and_issue(
            jwt_token,
            siwe,
            signature,
            self.f.mcp_header() if mcp is None else mcp,
            self.f.request if request is None else request,
            self.f.now,
            "grant-" + secrets.token_hex(8) if grant_id is None else grant_id,
        )

    def denied(self, code, **kwargs):
        with self.assertRaises(SecurityError) as caught:
            self.issue(**kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_positive_chain_and_independent_grant_verification(self):
        result = self.issue()
        self.assertEqual(
            result["sequence"],
            ["AUTHENTICATE", "AUTHORIZE", "CONFINED_EXECUTION_PENDING"],
        )
        self.assertEqual(result["authorization"]["verdict"], "ALLOW")
        payload = verify_execution_grant(
            result["grant"],
            self.f.grant_key.public_key(),
            self.f.grant_nonces,
            self.f.now,
            self.f.binding,
        )
        self.assertEqual(payload["binding_sha256"], self.f.binding.digest())

    def test_evidence_excludes_raw_credentials(self):
        token = self.f.make_jwt()
        message, signature = self.f.make_siwe()
        result = self.issue(jwt_token=token, siwe=message, signature=signature)
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn(token, encoded)
        self.assertNotIn(self.f.mcp_token, encoded)
        self.assertNotIn(signature, encoded)
        self.assertNotIn(message, encoded)

    def test_jwt_forged_signing_key(self):
        self.denied("JWT_CRYPTO_OR_CLAIMS", jwt_token=self.f.make_jwt(key=self.f.wrong_key))

    def test_jwt_malformed(self):
        self.denied("JWT_HEADER", jwt_token="not-a-jwt")

    def test_jwt_algorithm_confusion_rejected(self):
        claims = self.f.jwt_claims()
        confused = jwt.encode(claims, "local-hmac-key-with-at-least-32-bytes", algorithm="HS256", headers={"kid": "key-1", "typ": "JWT"})
        self.denied("JWT_ALGORITHM", jwt_token=confused)

    def test_jwt_expired(self):
        self.denied("JWT_CRYPTO_OR_CLAIMS", jwt_token=self.f.make_jwt(exp=self.f.now - 1))

    def test_jwt_future_nbf(self):
        self.denied("JWT_CRYPTO_OR_CLAIMS", jwt_token=self.f.make_jwt(nbf=self.f.now + 60))

    def test_jwt_future_iat(self):
        self.denied("JWT_CRYPTO_OR_CLAIMS", jwt_token=self.f.make_jwt(iat=self.f.now + 60))

    def test_jwt_wrong_issuer(self):
        self.denied("JWT_CRYPTO_OR_CLAIMS", jwt_token=self.f.make_jwt(iss="https://wrong.local"))

    def test_jwt_cross_service_audience(self):
        self.denied("JWT_CRYPTO_OR_CLAIMS", jwt_token=self.f.make_jwt(aud="other-service"))

    def test_jwt_missing_required_claim(self):
        claims = self.f.jwt_claims()
        del claims["resource_id"]
        token = jwt.encode(claims, self.f.key1, algorithm="RS256", headers={"kid": "key-1", "typ": "JWT"})
        self.denied("JWT_CRYPTO_OR_CLAIMS", jwt_token=token)

    def test_jwt_extra_claim_rejected(self):
        self.denied("JWT_CLAIMS_SHAPE", jwt_token=self.f.make_jwt(extra="not-allowed"))

    def test_jwt_replay(self):
        token = self.f.make_jwt()
        message, signature = self.f.make_siwe()
        self.issue(jwt_token=token, siwe=message, signature=signature)
        second_message, second_signature = self.f.make_siwe()
        self.denied("REPLAY_DETECTED", jwt_token=token, siwe=second_message, signature=second_signature)

    def test_jwt_revoked_key(self):
        record = self.f.trust.jwt_keys["key-1"]
        self.f.trust.jwt_keys["key-1"] = replace(record, revoked=True)
        self.denied("JWT_KEY_REVOKED")

    def test_jwt_expired_key(self):
        record = self.f.trust.jwt_keys["key-1"]
        self.f.trust.jwt_keys["key-1"] = replace(record, expires_at=self.f.now)
        self.denied("JWT_KEY_EXPIRED")

    def test_jwt_key_not_yet_valid(self):
        record = self.f.trust.jwt_keys["key-1"]
        self.f.trust.jwt_keys["key-1"] = replace(record, not_before=self.f.now + 60)
        self.denied("JWT_KEY_NOT_YET_VALID")

    def test_jwt_rotation_second_key(self):
        result = self.issue(jwt_token=self.f.make_jwt(key=self.f.key2, kid="key-2"))
        self.assertEqual(result["authorization"]["verdict"], "ALLOW")

    def test_jwt_token_cannot_outlive_key(self):
        record = self.f.trust.jwt_keys["key-1"]
        self.f.trust.jwt_keys["key-1"] = replace(record, expires_at=self.f.now + 30)
        self.denied("JWT_OUTLIVES_KEY")

    def test_jwt_role_not_registered(self):
        self.denied("JWT_ROLE", jwt_token=self.f.make_jwt(role="ROOT"))

    def test_jwt_wallet_subject_mismatch(self):
        self.denied("JWT_WALLET_SUBJECT", jwt_token=self.f.make_jwt(sub="other-subject"))

    def test_jwt_wallet_address_mismatch(self):
        self.denied("WALLET_UNREGISTERED", jwt_token=self.f.make_jwt(wallet=self.f.other_wallet.address))

    def test_jwt_agent_binding(self):
        self.denied("JWT_REQUEST_BINDING", jwt_token=self.f.make_jwt(agent_id="agent-other"))

    def test_jwt_resource_binding(self):
        self.denied("JWT_REQUEST_BINDING", jwt_token=self.f.make_jwt(resource_id="resource-other"))

    def test_jwt_tool_binding(self):
        self.denied("JWT_REQUEST_BINDING", jwt_token=self.f.make_jwt(tool="shell"))

    def test_jwt_destination_binding(self):
        self.denied("JWT_REQUEST_BINDING", jwt_token=self.f.make_jwt(destination="https://evil.invalid"))

    def test_jwt_body_binding(self):
        self.denied("JWT_REQUEST_BINDING", jwt_token=self.f.make_jwt(body_sha256="0" * 64))

    def test_siwe_forged_signature(self):
        message, _ = self.f.make_siwe()
        other = Account.create()
        _, signature = self.f.make_siwe(account=other)
        self.denied("SIWE_CRYPTO_OR_TIME", siwe=message, signature=signature)

    def test_siwe_malformed_message(self):
        _, signature = self.f.make_siwe()
        self.denied("SIWE_PARSE", siwe="not-an-eip-4361-message", signature=signature)

    def test_siwe_wrong_wallet(self):
        message, signature = self.f.make_siwe(account=self.f.other_wallet)
        self.denied("WALLET_UNREGISTERED", siwe=message, signature=signature)

    def test_siwe_wallet_resource_registry_binding(self):
        self.f.replace_wallet(resource_ids=frozenset())
        message, signature = self.f.make_siwe()
        with self.assertRaises(SecurityError) as caught:
            authenticate_siwe(
                message,
                signature,
                self.f.binding,
                self.f.trust,
                self.f.siwe_nonces,
                self.f.now,
            )
        self.assertEqual(caught.exception.code, "SIWE_WALLET_RESOURCE")

    def test_siwe_wrong_domain(self):
        message, signature = self.f.make_siwe(domain="wrong.local")
        self.denied("SIWE_CRYPTO_OR_TIME", siwe=message, signature=signature)

    def test_siwe_wrong_chain(self):
        message, signature = self.f.make_siwe(chain_id=1)
        self.denied("SIWE_DOMAIN_BINDING", siwe=message, signature=signature)

    def test_siwe_wrong_uri(self):
        message, signature = self.f.make_siwe(uri="https://guardian.local/other")
        self.denied("SIWE_REQUEST_BINDING", siwe=message, signature=signature)

    def test_siwe_expired(self):
        message, signature = self.f.make_siwe(expiration_time=datetime.fromtimestamp(self.f.now, timezone.utc))
        self.denied("SIWE_CRYPTO_OR_TIME", siwe=message, signature=signature)

    def test_siwe_future_not_before(self):
        message, signature = self.f.make_siwe(not_before=datetime.fromtimestamp(self.f.now + 60, timezone.utc))
        self.denied("SIWE_CRYPTO_OR_TIME", siwe=message, signature=signature)

    def test_siwe_resource_substitution(self):
        resources = ["urn:guardian:agent:other"]
        message, signature = self.f.make_siwe(resources=resources)
        self.denied("SIWE_RESOURCE_BINDING", siwe=message, signature=signature)

    def test_siwe_nonce_replay(self):
        nonce = "noncefixed1234"
        message, signature = self.f.make_siwe(nonce=nonce)
        self.issue(siwe=message, signature=signature)
        second_token = self.f.make_jwt()
        self.denied("REPLAY_DETECTED", jwt_token=second_token, siwe=message, signature=signature)

    def test_mcp_wrong_bearer(self):
        self.denied("MCP_BEARER_UNKNOWN", mcp="Bearer wrong-local-token")

    def test_mcp_revoked(self):
        self.f.replace_mcp(revoked=True)
        self.denied("MCP_BEARER_REVOKED")

    def test_mcp_expired(self):
        self.f.replace_mcp(expires_at=self.f.now)
        self.denied("MCP_BEARER_TIME")

    def test_mcp_not_yet_valid(self):
        self.f.replace_mcp(not_before=self.f.now + 60)
        self.denied("MCP_BEARER_TIME")

    def test_mcp_scope(self):
        self.f.replace_mcp(scopes=frozenset({"mcp:invoke"}))
        self.denied("MCP_SCOPE")

    def test_mcp_tool_substitution(self):
        self.f.replace_mcp(tool="shell")
        self.denied("MCP_REQUEST_BINDING")

    def test_mcp_destination_substitution(self):
        self.f.replace_mcp(destination="mcp://local/other")
        self.denied("MCP_REQUEST_BINDING")

    def test_valid_signatures_do_not_override_registry_owner(self):
        self.f.trust.resource_owners[self.f.binding.resource_id] = "other-subject"
        self.denied("RESOURCE_OWNER")

    def test_valid_signatures_do_not_override_role(self):
        self.f.request["operation"] = "ADMIN_ACTION"
        self.f.binding = RequestBinding.from_request(self.f.request)
        self.denied("ROLE_OPERATION")

    def test_payload_mutation_after_authorization_invalidates_grant(self):
        result = self.issue()
        mutated = copy.deepcopy(self.f.request)
        mutated["body"]["value"] = 8
        with self.assertRaises(SecurityError) as caught:
            verify_execution_grant(
                result["grant"],
                self.f.grant_key.public_key(),
                self.f.grant_nonces,
                self.f.now,
                RequestBinding.from_request(mutated),
            )
        self.assertEqual(caught.exception.code, "GRANT_REQUEST_BINDING")

    def test_grant_payload_mutation(self):
        result = self.issue()
        result["grant"]["payload"]["tool"] = "shell"
        with self.assertRaises(SecurityError) as caught:
            verify_execution_grant(result["grant"], self.f.grant_key.public_key(), self.f.grant_nonces, self.f.now)
        self.assertEqual(caught.exception.code, "GRANT_SIGNATURE")

    def test_grant_wrong_key(self):
        result = self.issue()
        with self.assertRaises(SecurityError) as caught:
            verify_execution_grant(result["grant"], Ed25519PrivateKey.generate().public_key(), self.f.grant_nonces, self.f.now)
        self.assertEqual(caught.exception.code, "GRANT_SIGNATURE")

    def test_grant_replay(self):
        result = self.issue()
        verify_execution_grant(result["grant"], self.f.grant_key.public_key(), self.f.grant_nonces, self.f.now)
        with self.assertRaises(SecurityError) as caught:
            verify_execution_grant(result["grant"], self.f.grant_key.public_key(), self.f.grant_nonces, self.f.now)
        self.assertEqual(caught.exception.code, "REPLAY_DETECTED")

    def test_trust_root_unavailable(self):
        self.f.trust.available = False
        self.denied("TRUST_ROOT_UNAVAILABLE")

    def test_trust_root_inconsistent(self):
        self.f.trust.consistent = False
        self.denied("TRUST_ROOT_INCONSISTENT")

    def test_trust_root_stale(self):
        self.f.trust.observed_at = self.f.now - self.f.trust.max_staleness - 1
        self.denied("TRUST_ROOT_STALE")

    def test_wallet_registry_expired(self):
        self.f.replace_wallet(expires_at=self.f.now)
        self.denied("WALLET_REGISTRY_EXPIRED")

    def test_wallet_registry_revoked(self):
        self.f.replace_wallet(revoked=True)
        self.denied("WALLET_REVOKED")

    def test_trust_root_future_observation(self):
        self.f.trust.observed_at = self.f.now + 6
        self.denied("TRUST_ROOT_FUTURE")

    def test_nonce_store_capacity_fails_closed(self):
        store = BoundedNonceStore(capacity=1, ttl_seconds=60)
        store.consume("test", "nonce-one", self.f.now)
        with self.assertRaises(SecurityError) as caught:
            store.consume("test", "nonce-two", self.f.now)
        self.assertEqual(caught.exception.code, "NONCE_STORE_FULL")

    def test_concurrent_replay_exactly_one_authorized(self):
        token = self.f.make_jwt()
        message, signature = self.f.make_siwe()
        barrier = threading.Barrier(8)
        results = []
        lock = threading.Lock()

        def worker(index):
            barrier.wait()
            try:
                self.issue(
                    jwt_token=token,
                    siwe=message,
                    signature=signature,
                    grant_id="grant-concurrent-" + str(index),
                )
                outcome = "ALLOW"
            except SecurityError as error:
                outcome = error.code
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(results.count("ALLOW"), 1)
        self.assertEqual(results.count("REPLAY_DETECTED"), 7)


if __name__ == "__main__":
    unittest.main()
