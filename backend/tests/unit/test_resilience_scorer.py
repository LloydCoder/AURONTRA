"""
Unit tests for resilience scoring engine.
RED → GREEN cycle.
"""
import pytest


class TestResilienceScorer:
    @pytest.mark.asyncio
    async def test_score_returns_dict_with_required_keys(self):
        from resilience.scorer import score_device
        result = await score_device("dev-001", {
            "cpu_percent": 40,
            "memory_percent": 55,
            "disk_percent": 60,
        })
        assert "device_id" in result
        assert "score" in result
        assert "status" in result
        assert "components" in result

    @pytest.mark.asyncio
    async def test_score_is_in_valid_range(self):
        from resilience.scorer import score_device
        result = await score_device("dev-002", {
            "cpu_percent": 20,
            "memory_percent": 30,
            "disk_percent": 40,
        })
        assert 0 <= result["score"] <= 100

    @pytest.mark.asyncio
    async def test_healthy_device_scores_above_80(self):
        from resilience.scorer import score_device
        result = await score_device("dev-003", {
            "cpu_percent": 15,
            "memory_percent": 25,
            "disk_percent": 30,
        })
        assert result["score"] >= 80
        assert result["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_stressed_device_scores_below_60(self):
        from resilience.scorer import score_device
        result = await score_device("dev-004", {
            "cpu_percent": 95,
            "memory_percent": 92,
            "disk_percent": 88,
        })
        assert result["score"] < 60

    @pytest.mark.asyncio
    async def test_critical_disk_triggers_critical_status(self):
        from resilience.scorer import score_device
        result = await score_device("dev-005", {
            "cpu_percent": 20,
            "memory_percent": 30,
            "disk_percent": 96,
        })
        assert result["status"] in ("warning", "critical")

    @pytest.mark.asyncio
    async def test_score_returns_correct_device_id(self):
        from resilience.scorer import score_device
        result = await score_device("specific-device-xyz", {
            "cpu_percent": 50,
            "memory_percent": 50,
            "disk_percent": 50,
        })
        assert result["device_id"] == "specific-device-xyz"

    @pytest.mark.asyncio
    async def test_empty_telemetry_returns_unknown_status(self):
        from resilience.scorer import score_device
        result = await score_device("dev-006", {})
        assert result["status"] == "unknown"


class TestResilienceStatus:
    def test_status_thresholds(self):
        from resilience.scorer import score_to_status
        assert score_to_status(90) == "healthy"
        assert score_to_status(70) == "healthy"
        assert score_to_status(59) == "warning"
        assert score_to_status(39) == "critical"
        assert score_to_status(0) == "critical"
