"""
Unit tests for bridge clients — all HTTP calls mocked.
RED → GREEN cycle.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestThreatFadeBridge:
    @pytest.mark.asyncio
    async def test_health_check_returns_true_on_200(self):
        with patch("bridges.threatfade.httpx.AsyncClient") as MockClient:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            instance = MockClient.return_value.__aenter__.return_value
            instance.get = AsyncMock(return_value=mock_resp)
            from bridges.threatfade import health_check
            result = await health_check()
            assert result is True

    @pytest.mark.asyncio
    async def test_health_check_returns_false_on_connection_error(self):
        with patch("bridges.threatfade.httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value.__aenter__.return_value
            instance.get = AsyncMock(side_effect=Exception("Connection refused"))
            from bridges.threatfade import health_check
            result = await health_check()
            assert result is False

    @pytest.mark.asyncio
    async def test_detect_scenario_posts_to_correct_endpoint(self):
        mock_response_data = {"threat_level": "high", "z_score": 14.76}
        with patch("bridges.threatfade.httpx.AsyncClient") as MockClient:
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_response_data
            mock_resp.raise_for_status = MagicMock()
            instance = MockClient.return_value.__aenter__.return_value
            instance.post = AsyncMock(return_value=mock_resp)
            from bridges.threatfade import detect_scenario
            result = await detect_scenario("c2_beacon")
            assert result == mock_response_data
            instance.post.assert_called_once()
            call_args = instance.post.call_args
            assert "/detect/scenario" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_get_events_returns_list(self):
        mock_events = [{"event": "c2_detected"}, {"event": "ticket_resolved"}]
        with patch("bridges.threatfade.httpx.AsyncClient") as MockClient:
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_events
            mock_resp.raise_for_status = MagicMock()
            instance = MockClient.return_value.__aenter__.return_value
            instance.get = AsyncMock(return_value=mock_resp)
            from bridges.threatfade import get_events
            result = await get_events(limit=10)
            assert isinstance(result, list)
            assert len(result) == 2


class TestFusionOpsBridge:
    @pytest.mark.asyncio
    async def test_get_events_calls_correct_url(self):
        with patch("bridges.fusionops.httpx.AsyncClient") as MockClient:
            mock_resp = MagicMock()
            mock_resp.json.return_value = []
            mock_resp.raise_for_status = MagicMock()
            instance = MockClient.return_value.__aenter__.return_value
            instance.get = AsyncMock(return_value=mock_resp)
            from bridges.fusionops import get_events
            await get_events()
            call_url = instance.get.call_args[0][0]
            assert "/events" in call_url
