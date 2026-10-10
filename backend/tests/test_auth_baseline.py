"""Security regression tests for Aurontra's production-default API gate."""
from fastapi.testclient import TestClient
import pytest
from core.config import settings
from main import app

def test_business_api_is_closed_when_identity_provider_is_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "required")
    monkeypatch.setattr(settings, "JWT_JWKS_URL", "")
    monkeypatch.setattr(settings, "JWT_ISSUER", "")
    monkeypatch.setattr(settings, "JWT_AUDIENCE", "")
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", True)
    with TestClient(app) as client:
        response = client.get("/tickets/")
    assert response.status_code == 503
    assert response.json()["code"] == "AUTH_PROVIDER_NOT_CONFIGURED"

def test_business_api_requires_bearer_token_when_auth_is_configured(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "required")
    monkeypatch.setattr(settings, "JWT_JWKS_URL", "https://issuer.example/.well-known/jwks.json")
    monkeypatch.setattr(settings, "JWT_ISSUER", "https://issuer.example")
    monkeypatch.setattr(settings, "JWT_AUDIENCE", "aurontra-api")
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", True)
    with TestClient(app) as client:
        response = client.get("/tickets/")
    assert response.status_code == 401
    assert response.json()["code"] == "AUTHENTICATION_REQUIRED"

def test_business_api_remains_closed_when_tenant_store_is_not_ready(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "disabled")
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", False)
    with TestClient(app) as client:
        response = client.get("/tickets/")
    assert response.status_code == 503
    assert response.json()["code"] == "TENANT_DATA_PLANE_NOT_READY"

def test_liveness_is_public(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "required")
    monkeypatch.setattr(settings, "JWT_JWKS_URL", "")
    monkeypatch.setattr(settings, "JWT_ISSUER", "")
    monkeypatch.setattr(settings, "JWT_AUDIENCE", "")
    with TestClient(app) as client:
        response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["alive"] is True


def test_production_cannot_disable_authentication(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "TEST_MODE", False)
    monkeypatch.setattr(settings, "AUTH_MODE", "disabled")
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", False)
    with TestClient(app) as client:
        response = client.get("/tickets/")
    assert response.status_code == 503
    assert response.json()["code"] == "PRODUCTION_AUTH_REQUIRED"


def test_data_plane_cannot_be_enabled_before_tenant_isolation_is_implemented(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(settings, "AUTH_MODE", "disabled")
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", True)
    monkeypatch.setattr(settings, "TEST_MODE", False)
    with TestClient(app) as client:
        response = client.get("/tickets/")
    assert response.status_code == 503
    assert response.json()["code"] == "TENANT_DATA_PLANE_NOT_READY"


def test_oversized_request_is_rejected_before_route_processing(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "disabled")
    monkeypatch.setattr(settings, "MAX_REQUEST_BODY_BYTES", 16)
    with TestClient(app) as client:
        response = client.post("/tickets/ingest", content=b"x" * 17, headers={"content-type": "application/json"})
    assert response.status_code == 413
    assert response.json()["code"] == "REQUEST_BODY_TOO_LARGE"


def test_production_cannot_enable_test_mode(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "TEST_MODE", True)
    monkeypatch.setattr(settings, "AUTH_MODE", "disabled")
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", False)
    with TestClient(app) as client:
        response = client.get("/tickets/")
    assert response.status_code == 503
    assert response.json()["code"] == "PRODUCTION_TEST_MODE_FORBIDDEN"


@pytest.mark.asyncio
async def test_production_closed_mode_does_not_mutate_database_schema(monkeypatch):
    from core.database import Base, init_db
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", False)
    def forbidden_create_all(*args, **kwargs):
        pytest.fail("production closed mode must not call metadata.create_all")
    monkeypatch.setattr(Base.metadata, "create_all", forbidden_create_all)
    await init_db()


def test_role_policy_allows_viewer_read_but_denies_mutation():
    from core.auth import AuthorizationDenied, authorize_claims
    claims = {"sub": "user_1", "org_id": "org_1", "org_role": "org:viewer"}
    assert authorize_claims(claims, "GET", "/tickets/")["tenant_id"] == "org_1"
    with pytest.raises(AuthorizationDenied):
        authorize_claims(claims, "POST", "/tickets/ingest")


def test_role_policy_restricts_privileged_operations_to_admin():
    from core.auth import AuthorizationDenied, authorize_claims
    member = {"sub": "user_2", "org_id": "org_1", "org_role": "org:member"}
    with pytest.raises(AuthorizationDenied):
        authorize_claims(member, "POST", "/automation/trigger")
    admin = {"sub": "user_3", "org_id": "org_1", "org_role": "org:admin"}
    assert authorize_claims(admin, "POST", "/automation/trigger")["role"] == "org:admin"


def test_role_policy_denies_missing_or_unknown_role():
    from core.auth import AuthorizationDenied, authorize_claims
    with pytest.raises(AuthorizationDenied):
        authorize_claims({"sub": "user_1", "org_id": "org_1"}, "GET", "/tickets/")
    with pytest.raises(AuthorizationDenied):
        authorize_claims({"sub": "user_1", "org_id": "org_1", "org_role": "superuser"}, "GET", "/tickets/")


def test_production_rejects_http_identity_provider_endpoints(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "TEST_MODE", False)
    monkeypatch.setattr(settings, "AUTH_MODE", "required")
    monkeypatch.setattr(settings, "JWT_JWKS_URL", "http://issuer.example/jwks.json")
    monkeypatch.setattr(settings, "JWT_ISSUER", "http://issuer.example")
    monkeypatch.setattr(settings, "JWT_AUDIENCE", "aurontra-api")
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", False)
    with TestClient(app) as client:
        response = client.get("/tickets/")
    assert response.status_code == 503
    assert response.json()["code"] == "AUTH_PROVIDER_CONFIG_INVALID"


def test_jwt_verifier_accepts_valid_signature_and_required_claims(monkeypatch):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from core import auth

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    class SigningKey:
        key = private_key.public_key()
    class FakeJwksClient:
        def get_signing_key_from_jwt(self, token):
            return SigningKey()

    monkeypatch.setattr(auth, "_jwks_client", lambda: FakeJwksClient())
    monkeypatch.setattr(settings, "JWT_JWKS_URL", "https://issuer.example/jwks.json")
    monkeypatch.setattr(settings, "JWT_ISSUER", "https://issuer.example")
    monkeypatch.setattr(settings, "JWT_AUDIENCE", "aurontra-api")
    now = int(__import__("time").time())
    token = jwt.encode(
        {"sub": "user_123", "org_id": "org_123", "iss": "https://issuer.example",
         "aud": "aurontra-api", "iat": now, "exp": now + 60},
        private_key, algorithm="RS256", headers={"kid": "test-key"},
    )
    claims = auth.verify_bearer_token(token)
    assert claims["sub"] == "user_123"
    assert claims["org_id"] == "org_123"


def test_jwt_verifier_rejects_wrong_signature(monkeypatch):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from core import auth

    trusted_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    class SigningKey:
        key = trusted_key.public_key()
    class FakeJwksClient:
        def get_signing_key_from_jwt(self, token):
            return SigningKey()

    monkeypatch.setattr(auth, "_jwks_client", lambda: FakeJwksClient())
    monkeypatch.setattr(settings, "JWT_JWKS_URL", "https://issuer.example/jwks.json")
    monkeypatch.setattr(settings, "JWT_ISSUER", "https://issuer.example")
    monkeypatch.setattr(settings, "JWT_AUDIENCE", "aurontra-api")
    now = int(__import__("time").time())
    token = jwt.encode(
        {"sub": "user_123", "org_id": "org_123", "iss": "https://issuer.example",
         "aud": "aurontra-api", "iat": now, "exp": now + 60},
        attacker_key, algorithm="RS256", headers={"kid": "attacker-key"},
    )
    with pytest.raises(jwt.InvalidSignatureError):
        auth.verify_bearer_token(token)


def test_signed_webhook_is_not_required_to_present_user_bearer_token(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(settings, "AUTH_MODE", "required")
    monkeypatch.setattr(settings, "JWT_JWKS_URL", "")
    monkeypatch.setattr(settings, "JWT_ISSUER", "")
    monkeypatch.setattr(settings, "JWT_AUDIENCE", "")
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", False)
    monkeypatch.setattr(settings, "TEST_MODE", False)
    with TestClient(app) as client:
        response = client.post("/billing/webhook", content=b'{"meta":{}}', headers={"content-type": "application/json"})
    assert response.status_code == 503
    assert response.json()["code"] == "TENANT_DATA_PLANE_NOT_READY"
