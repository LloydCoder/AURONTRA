"""Security regression tests for Aurontra's production-default API gate."""
from fastapi.testclient import TestClient
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
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", True)
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
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", True)
    with TestClient(app) as client:
        response = client.get("/tickets/")
    assert response.status_code == 503
    assert response.json()["code"] == "PRODUCTION_TEST_MODE_FORBIDDEN"
