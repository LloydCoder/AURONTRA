"""Bridge adapter contract tests; outbound network access is never required."""
import pytest
from unittest.mock import AsyncMock, patch

from core.tsic_contracts import TSICIdentityContext


def _identity_context():
    return TSICIdentityContext(
        tenant_id="tenant-1", organization_id="org-1", workspace_id="workspace-1",
        actor_id="service:aurontra", execution_id="execution-1",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736", correlation_id="correlation-1",
    )


class TestThreatFadeBridge:
    @pytest.mark.asyncio
    async def test_health_check_requires_healthy_contract_response(self, monkeypatch):
        monkeypatch.setattr("bridges.threatfade.settings.THREATFADE_URL", "https://threatfade.example")
        with patch("bridges.threatfade.request_json", new=AsyncMock(return_value={"status": "ok"})) as call:
            from bridges.threatfade import health_check
            assert await health_check() is True
            assert call.await_args.kwargs["service"] == "threatfade"
            assert call.await_args.kwargs["path"] == "/health"

    @pytest.mark.asyncio
    async def test_health_check_fails_closed_on_integration_error(self, monkeypatch):
        monkeypatch.setattr("bridges.threatfade.settings.THREATFADE_URL", "https://threatfade.example")
        with patch("bridges.threatfade.request_json", new=AsyncMock(side_effect=RuntimeError("private detail"))):
            from bridges.threatfade import health_check
            assert await health_check() is False

    @pytest.mark.asyncio
    async def test_detection_post_is_not_retried_by_adapter_without_idempotency_key(self):
        with patch("bridges.threatfade.request_json", new=AsyncMock(return_value={"threat_level": "high"})) as call:
            from bridges.threatfade import detect_scenario
            result = await detect_scenario("c2_beacon", identity_context=_identity_context())
        assert result == {"threat_level": "high"}
        assert call.await_args.kwargs["method"] == "POST"
        assert call.await_args.kwargs["path"] == "/detect/scenario"
        assert call.await_args.kwargs["identity_context"] == _identity_context()
        assert "idempotency_key" not in call.await_args.kwargs

    @pytest.mark.asyncio
    async def test_get_events_enforces_bounded_limit(self):
        from bridges.threatfade import get_events
        with pytest.raises(ValueError):
            await get_events(10000, identity_context=_identity_context())
        with patch("bridges.threatfade.request_json", new=AsyncMock(return_value=[])) as call:
            assert await get_events(10, identity_context=_identity_context()) == []
            assert call.await_args.kwargs["params"] == {"limit": 10}


class TestFusionOpsBridge:
    @pytest.mark.asyncio
    async def test_get_events_uses_versioned_ecosystem_client(self):
        with patch("bridges.fusionops.request_json", new=AsyncMock(return_value=[])) as call:
            from bridges.fusionops import get_events
            assert await get_events(identity_context=_identity_context()) == []
        assert call.await_args.kwargs["service"] == "fusionops"
        assert call.await_args.kwargs["path"] == "/events"

    @pytest.mark.asyncio
    async def test_health_check_fails_closed(self):
        with patch("bridges.fusionops.request_json", new=AsyncMock(side_effect=RuntimeError())):
            from bridges.fusionops import health_check
            assert await health_check() is False
