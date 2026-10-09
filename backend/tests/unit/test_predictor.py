"""
Sprint 4 — Predictive Resilience Engine tests.
RED phase: all tests written before implementation.
"""
import pytest
import numpy as np


class TestIsolationForestPredictor:
    """Tests for the Isolation Forest anomaly detection model."""

    def test_predictor_trains_without_error(self):
        from resilience.predictor import ResiliencePredictor
        predictor = ResiliencePredictor()
        data = [
            {"cpu_percent": 20, "memory_percent": 30, "disk_percent": 40},
            {"cpu_percent": 25, "memory_percent": 35, "disk_percent": 42},
            {"cpu_percent": 22, "memory_percent": 28, "disk_percent": 38},
            {"cpu_percent": 18, "memory_percent": 32, "disk_percent": 45},
            {"cpu_percent": 21, "memory_percent": 31, "disk_percent": 41},
        ]
        predictor.train(data)
        assert predictor.is_trained is True

    def test_predictor_requires_minimum_samples(self):
        from resilience.predictor import ResiliencePredictor
        predictor = ResiliencePredictor()
        with pytest.raises(ValueError):
            predictor.train([{"cpu_percent": 20}])

    def test_normal_reading_is_not_anomaly(self):
        from resilience.predictor import ResiliencePredictor
        predictor = ResiliencePredictor()
        normal_data = [
            {"cpu_percent": 20 + i, "memory_percent": 30 + i, "disk_percent": 40}
            for i in range(20)
        ]
        predictor.train(normal_data)
        result = predictor.predict({"cpu_percent": 22, "memory_percent": 33, "disk_percent": 40})
        assert "is_anomaly" in result
        assert "anomaly_score" in result
        assert result["is_anomaly"] is False

    def test_extreme_reading_is_anomaly(self):
        from resilience.predictor import ResiliencePredictor
        predictor = ResiliencePredictor()
        normal_data = [
            {"cpu_percent": 20, "memory_percent": 30, "disk_percent": 40}
            for _ in range(20)
        ]
        predictor.train(normal_data)
        result = predictor.predict({"cpu_percent": 99, "memory_percent": 98, "disk_percent": 97})
        assert result["is_anomaly"] is True

    def test_predict_without_training_raises(self):
        from resilience.predictor import ResiliencePredictor
        predictor = ResiliencePredictor()
        with pytest.raises(RuntimeError):
            predictor.predict({"cpu_percent": 50})

    def test_anomaly_score_is_float(self):
        from resilience.predictor import ResiliencePredictor
        predictor = ResiliencePredictor()
        data = [{"cpu_percent": 20 + i, "memory_percent": 30, "disk_percent": 40} for i in range(15)]
        predictor.train(data)
        result = predictor.predict({"cpu_percent": 25, "memory_percent": 30, "disk_percent": 40})
        assert isinstance(result["anomaly_score"], float)

    def test_predict_returns_confidence(self):
        from resilience.predictor import ResiliencePredictor
        predictor = ResiliencePredictor()
        data = [{"cpu_percent": 20, "memory_percent": 30, "disk_percent": 40} for _ in range(15)]
        predictor.train(data)
        result = predictor.predict({"cpu_percent": 25, "memory_percent": 30, "disk_percent": 40})
        assert "confidence" in result
        assert 0.0 <= result["confidence"] <= 1.0

    def test_model_can_be_serialised_and_loaded(self):
        import tempfile, os
        from resilience.predictor import ResiliencePredictor
        predictor = ResiliencePredictor()
        data = [{"cpu_percent": 20 + i, "memory_percent": 30, "disk_percent": 40} for i in range(15)]
        predictor.train(data)
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            path = f.name
        try:
            predictor.save(path)
            loaded = ResiliencePredictor.load(path)
            assert loaded.is_trained is True
            result = loaded.predict({"cpu_percent": 22, "memory_percent": 30, "disk_percent": 40})
            assert "is_anomaly" in result
        finally:
            os.unlink(path)


class TestTemporalCorrelator:
    """Tests for time-series failure prediction."""

    def test_correlator_accepts_time_series(self):
        from resilience.temporal import TemporalCorrelator
        tc = TemporalCorrelator()
        series = [
            {"timestamp": f"2026-06-20T{10+i:02d}:00:00Z",
             "cpu_percent": 20 + i * 3,
             "memory_percent": 30,
             "disk_percent": 40}
            for i in range(10)
        ]
        result = tc.analyse(series)
        assert "trend" in result
        assert "predicted_score_72h" in result
        assert "risk_factors" in result

    def test_rising_cpu_trend_predicts_lower_future_score(self):
        from resilience.temporal import TemporalCorrelator
        tc = TemporalCorrelator()
        # CPU rising fast — 20% → 80% over 10 readings
        series = [
            {"timestamp": f"2026-06-20T{i:02d}:00:00Z",
             "cpu_percent": 20 + i * 6,
             "memory_percent": 30,
             "disk_percent": 40}
            for i in range(10)
        ]
        result = tc.analyse(series)
        assert result["trend"] in ("rising", "degrading")
        assert result["predicted_score_72h"] < 80

    def test_stable_readings_predict_healthy_future_score(self):
        from resilience.temporal import TemporalCorrelator
        tc = TemporalCorrelator()
        series = [
            {"timestamp": f"2026-06-20T{i:02d}:00:00Z",
             "cpu_percent": 20,
             "memory_percent": 30,
             "disk_percent": 40}
            for i in range(10)
        ]
        result = tc.analyse(series)
        assert result["trend"] == "stable"
        assert result["predicted_score_72h"] >= 75

    def test_empty_series_raises(self):
        from resilience.temporal import TemporalCorrelator
        tc = TemporalCorrelator()
        with pytest.raises(ValueError):
            tc.analyse([])

    def test_single_reading_raises(self):
        from resilience.temporal import TemporalCorrelator
        tc = TemporalCorrelator()
        with pytest.raises(ValueError):
            tc.analyse([{"timestamp": "2026-06-20T00:00:00Z", "cpu_percent": 20}])

    def test_risk_factors_is_list(self):
        from resilience.temporal import TemporalCorrelator
        tc = TemporalCorrelator()
        series = [
            {"timestamp": f"2026-06-20T{i:02d}:00:00Z",
             "cpu_percent": 50,
             "memory_percent": 50,
             "disk_percent": 50}
            for i in range(5)
        ]
        result = tc.analyse(series)
        assert isinstance(result["risk_factors"], list)

    def test_disk_growth_flagged_as_risk_factor(self):
        from resilience.temporal import TemporalCorrelator
        tc = TemporalCorrelator()
        series = [
            {"timestamp": f"2026-06-20T{i:02d}:00:00Z",
             "cpu_percent": 20,
             "memory_percent": 30,
             "disk_percent": 50 + i * 4}
            for i in range(10)
        ]
        result = tc.analyse(series)
        risk_text = " ".join(result["risk_factors"]).lower()
        assert "disk" in risk_text


class TestDeviceAgentTelemetry:
    """Tests for the lightweight device agent telemetry collector."""

    def test_collect_metrics_returns_required_keys(self):
        from agent.collector import collect_metrics
        result = collect_metrics(device_id="test-device-01")
        assert "device_id" in result
        assert "cpu_percent" in result
        assert "memory_percent" in result
        assert "disk_percent" in result
        assert "timestamp" in result

    def test_cpu_percent_is_valid_range(self):
        from agent.collector import collect_metrics
        result = collect_metrics(device_id="test-device-01")
        assert 0.0 <= result["cpu_percent"] <= 100.0

    def test_memory_percent_is_valid_range(self):
        from agent.collector import collect_metrics
        result = collect_metrics(device_id="test-device-01")
        assert 0.0 <= result["memory_percent"] <= 100.0

    def test_disk_percent_is_valid_range(self):
        from agent.collector import collect_metrics
        result = collect_metrics(device_id="test-device-01")
        assert 0.0 <= result["disk_percent"] <= 100.0

    def test_device_id_preserved(self):
        from agent.collector import collect_metrics
        result = collect_metrics(device_id="my-special-server")
        assert result["device_id"] == "my-special-server"

    def test_timestamp_is_iso_format(self):
        from agent.collector import collect_metrics
        from datetime import datetime
        result = collect_metrics(device_id="test")
        # Should parse without error
        dt = datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))
        assert dt is not None


class TestResilienceAPIEndpoints:
    """Integration tests for resilience scoring API endpoints."""

    @pytest.fixture
    async def client(self):
        from httpx import AsyncClient, ASGITransport
        from main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_resilience_score_endpoint(self, client):
        r = await client.post("/resilience/score", json={
            "device_id": "srv-001",
            "telemetry": {
                "cpu_percent": 25,
                "memory_percent": 40,
                "disk_percent": 55,
            },
        })
        assert r.status_code == 200
        data = r.json()
        assert "score" in data
        assert "status" in data

    @pytest.mark.asyncio
    async def test_resilience_predict_endpoint(self, client):
        r = await client.post("/resilience/predict", json={
            "device_id": "srv-001",
            "history": [
                {"timestamp": f"2026-06-20T{i:02d}:00:00Z",
                 "cpu_percent": 20 + i,
                 "memory_percent": 30,
                 "disk_percent": 40}
                for i in range(5)
            ],
        })
        assert r.status_code == 200
        data = r.json()
        assert "predicted_score_72h" in data
        assert "trend" in data

    @pytest.mark.asyncio
    async def test_resilience_history_endpoint(self, client):
        r = await client.get("/resilience/history/srv-001")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_devices_telemetry_updates_resilience(self, client):
        r = await client.post("/devices/telemetry", json={
            "device_id": "srv-002",
            "cpu_percent": 30.0,
            "memory_percent": 45.0,
            "disk_percent": 60.0,
        })
        assert r.status_code == 200
        data = r.json()
        assert data["resilience"]["score"] >= 60
