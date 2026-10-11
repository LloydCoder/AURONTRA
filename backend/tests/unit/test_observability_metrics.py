"""SRE metrics and health endpoint regressions."""
import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from observability.metrics import ProcessMetrics


def test_metrics_use_route_templates_and_report_slo_snapshot():
    registry = ProcessMetrics()
    registry.record("GET", "/devices/{device_id}", 200, 0.05)
    registry.record("GET", "/devices/{device_id}", 500, 0.7)
    registry.record("POST", "/tickets", 201, 0.02)
    snapshot = registry.snapshot()
    rendered = registry.render_prometheus()

    assert snapshot["request_count"] == 3
    assert snapshot["server_error_count"] == 1
    assert snapshot["server_error_rate"] == pytest.approx(1 / 3)
    assert snapshot["durable"] is False
    assert "/devices/{device_id}" in rendered
    assert "device-123" not in rendered
    assert "aurontra_http_request_duration_seconds_bucket" in rendered
    assert "aurontra_metrics_process_local 1" in rendered


@pytest.mark.asyncio
async def test_health_liveness_is_independent_of_external_bridges():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"alive": True}


@pytest.mark.asyncio
async def test_bridge_health_checks_are_bounded(monkeypatch):
    from api.routes import health
    from bridges import threatfade

    async def slow_health():
        await asyncio.sleep(0.2)
        return True

    monkeypatch.setattr(threatfade, "health_check", slow_health)
    monkeypatch.setattr(health.settings, "THREATFADE_URL", "https://health-check.invalid")
    monkeypatch.setattr(health.settings, "BRIDGE_HEALTH_TIMEOUT_SECONDS", 0.01)
    result = await health._check_all_bridges()
    assert result["threatfade"] == "timeout"
    assert all(value == "not_configured" for name, value in result.items() if name != "threatfade")


@pytest.mark.asyncio
async def test_slo_and_metrics_endpoints_are_available_when_enabled():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        metrics_response = await client.get("/health/metrics")
        slo_response = await client.get("/health/slo")
    assert metrics_response.status_code == 200
    assert "aurontra_http_requests_total" in metrics_response.text
    assert slo_response.status_code == 200
    assert slo_response.json()["durable"] is False
    assert slo_response.json()["window"] == "process_lifetime"


@pytest.mark.asyncio
async def test_production_readiness_fails_closed_when_data_plane_is_disabled(monkeypatch):
    from fastapi import Response
    from api.routes import health
    monkeypatch.setattr(health.settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(health.settings, "DATA_PLANE_ENABLED", False)
    response = Response()
    result = await health.readiness(response, db=None)
    assert response.status_code == 503
    assert result["ready"] is False
    assert result["business_data_plane_ready"] is False
