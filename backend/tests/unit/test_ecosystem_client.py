"""Security and resilience tests for the shared Tinlance ecosystem client."""
import json

import httpx
import pytest

from core.config import settings
from core.ecosystem_client import (
    EcosystemIntegrationError,
    request_json,
    reset_circuits_for_tests,
)


@pytest.fixture
def identity_context():
    return {
        "tenant_id": "tenant-1",
        "organization_id": "org-1",
        "workspace_id": "workspace-1",
        "actor_id": "service:aurontra",
        "execution_id": "execution-1",
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "correlation_id": "correlation-1",
    }


def event_payload(context, **overrides):
    event = {
        "id": "event-1",
        "source": "aurontra",
        "specversion": "1.0",
        "type": "aurontra.telemetry.accepted",
        "time": "2026-10-11T08:00:00Z",
        "subject": "device:device-1",
        "data": {"status": "accepted"},
        "data_content_type": "application/json",
        "tenant_id": context["tenant_id"],
        "execution_id": context["execution_id"],
        "trace_id": context["trace_id"],
        "correlation_id": context["correlation_id"],
    }
    event.update(overrides)
    return event


@pytest.fixture(autouse=True)
def reset_circuit_state(monkeypatch):
    reset_circuits_for_tests()
    monkeypatch.setattr(settings, "BRIDGE_AUTH_TOKENS_JSON", json.dumps({
        "test-service": "t" * 48,
    }))
    monkeypatch.setattr(settings, "ENVIRONMENT", "test")
    monkeypatch.setattr(settings, "BRIDGE_ALLOW_INSECURE_HTTP", False)
    yield
    reset_circuits_for_tests()


@pytest.mark.asyncio
async def test_client_sends_bearer_and_versioned_contract_headers():
    seen = {}

    async def handler(request):
        seen.update(dict(request.headers))
        return httpx.Response(200, json={"status": "ok"})

    result = await request_json(
        service="test-service",
        base_url="https://integration.example",
        method="GET",
        path="/health",
        transport=httpx.MockTransport(handler),
    )
    assert result == {"status": "ok"}
    assert seen["authorization"] == "Bearer " + "t" * 48
    assert seen["x-tinlance-contract-version"] == "1.0.0"
    assert seen["traceparent"].startswith("00-")
    assert seen["x-trace-id"]
    assert seen["x-span-id"]
    assert seen["x-correlation-id"]
    assert seen["x-request-id"]


@pytest.mark.asyncio
async def test_client_preserves_valid_trace_context_and_correlation_id(identity_context):
    seen = {}
    traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

    async def handler(request):
        seen.update(dict(request.headers))
        return httpx.Response(200, json={"status": "ok"})

    await request_json(
        service="test-service",
        base_url="https://integration.example",
        method="GET",
        path="/health",
        traceparent=traceparent,
        correlation_id="correlation-1",
        identity_context=identity_context,
        transport=httpx.MockTransport(handler),
    )
    assert seen["traceparent"] == traceparent
    assert seen["x-trace-id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert seen["x-span-id"] == "00f067aa0ba902b7"
    assert seen["x-correlation-id"] == "correlation-1"
    assert seen["x-tinlance-tenant-id"] == "tenant-1"
    assert seen["x-tinlance-organization-id"] == "org-1"
    assert seen["x-tinlance-workspace-id"] == "workspace-1"
    assert seen["x-tinlance-actor-id"] == "service:aurontra"
    assert seen["x-tinlance-execution-id"] == "execution-1"


@pytest.mark.asyncio
async def test_client_rejects_invalid_trace_context_and_correlation_id():
    with pytest.raises(EcosystemIntegrationError) as trace_error:
        await request_json(
            service="test-service",
            base_url="https://integration.example",
            method="GET",
            path="/health",
            traceparent="00-" + "0" * 32 + "-" + "0" * 16 + "-01",
        )
    assert trace_error.value.code == "bridge_trace_context_invalid"

    with pytest.raises(EcosystemIntegrationError) as correlation_error:
        await request_json(
            service="test-service",
            base_url="https://integration.example",
            method="GET",
            path="/health",
            correlation_id="bad\r\nX-Injected: yes",
        )
    assert correlation_error.value.code == "bridge_correlation_id_invalid"


@pytest.mark.asyncio
async def test_client_fails_closed_without_per_service_credentials(monkeypatch):
    monkeypatch.setattr(settings, "BRIDGE_AUTH_TOKENS_JSON", "{}")
    with pytest.raises(EcosystemIntegrationError) as error:
        await request_json(
            service="test-service", base_url="https://integration.example",
            method="GET", path="/health",
        )
    assert error.value.code == "bridge_credentials_missing"


@pytest.mark.asyncio
async def test_production_rejects_plain_http(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    with pytest.raises(EcosystemIntegrationError) as error:
        await request_json(
            service="test-service", base_url="http://integration.example",
            method="GET", path="/health",
        )
    assert error.value.code == "bridge_https_required"


@pytest.mark.asyncio
async def test_origin_and_path_validation_prevent_url_injection():
    with pytest.raises(EcosystemIntegrationError):
        await request_json(
            service="test-service", base_url="https://user:pass@integration.example",
            method="GET", path="/health",
        )
    with pytest.raises(EcosystemIntegrationError):
        await request_json(
            service="test-service", base_url="https://integration.example",
            method="GET", path="//evil.example/steal",
        )


@pytest.mark.asyncio
async def test_retryable_get_retries_transient_upstream_failures(identity_context):
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, json={"detail": "untrusted upstream message"})
        return httpx.Response(200, json={"events": []})

    result = await request_json(
        service="test-service", base_url="https://integration.example",
        method="GET", path="/events", identity_context=identity_context,
        transport=httpx.MockTransport(handler),
    )
    assert result == {"events": []}
    assert calls == 2


@pytest.mark.asyncio
async def test_non_idempotent_post_is_not_retried(identity_context):
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={"detail": "retry must not happen"})

    with pytest.raises(EcosystemIntegrationError) as error:
        await request_json(
            service="test-service", base_url="https://integration.example",
            method="POST", path="/actions", payload={"action": "submit"},
            identity_context=identity_context, transport=httpx.MockTransport(handler),
        )
    assert error.value.code == "bridge_upstream_retryable"
    assert calls == 1


@pytest.mark.asyncio
async def test_post_retries_only_with_explicit_idempotency_key(identity_context):
    calls = 0
    keys = []

    async def handler(request):
        nonlocal calls
        calls += 1
        keys.append(request.headers.get("Idempotency-Key"))
        if calls == 1:
            return httpx.Response(503, json={})
        return httpx.Response(200, json={"accepted": True})

    result = await request_json(
        service="test-service", base_url="https://integration.example",
        method="POST", path="/events", payload=event_payload(identity_context),
        identity_context=identity_context, idempotency_key="event-123",
        transport=httpx.MockTransport(handler),
    )
    assert result == {"accepted": True}
    assert calls == 2
    assert keys == ["event-123", "event-123"]


@pytest.mark.asyncio
async def test_tenant_scoped_call_requires_identity_context():
    with pytest.raises(EcosystemIntegrationError) as error:
        await request_json(
            service="test-service", base_url="https://integration.example",
            method="GET", path="/events",
        )
    assert error.value.code == "bridge_identity_context_missing"


@pytest.mark.asyncio
async def test_event_envelope_must_match_verified_tenant_context(identity_context):
    async def handler(request):
        return httpx.Response(202, json={"accepted": True})

    with pytest.raises(EcosystemIntegrationError) as error:
        await request_json(
            service="test-service", base_url="https://integration.example",
            method="POST", path="/events",
            payload=event_payload(identity_context, tenant_id="other-tenant"),
            identity_context=identity_context, idempotency_key="event-1",
            transport=httpx.MockTransport(handler),
        )
    assert error.value.code == "bridge_event_context_mismatch"


@pytest.mark.asyncio
async def test_client_does_not_follow_redirects():
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(302, headers={"Location": "https://evil.example/"})

    with pytest.raises(EcosystemIntegrationError) as error:
        await request_json(
            service="test-service", base_url="https://integration.example",
            method="GET", path="/health", transport=httpx.MockTransport(handler),
        )
    assert error.value.code == "bridge_upstream_rejected"
    assert calls == 1


@pytest.mark.asyncio
async def test_repeated_upstream_failures_open_circuit_without_leaking_body():
    async def handler(request):
        return httpx.Response(503, json={"detail": "secret upstream diagnostic"})

    transport = httpx.MockTransport(handler)
    for _ in range(5):
        with pytest.raises(EcosystemIntegrationError):
            await request_json(
                service="test-service", base_url="https://integration.example",
                method="GET", path="/health", transport=transport,
            )

    with pytest.raises(EcosystemIntegrationError) as error:
        await request_json(
            service="test-service", base_url="https://integration.example",
            method="GET", path="/health", transport=transport,
        )
    assert error.value.code == "bridge_circuit_open"
    assert "secret" not in str(error.value)
