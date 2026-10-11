"""
Sprint 4 — Predictive Resilience Engine tests.
RED phase: all tests written before implementation.
"""
import pytest
import numpy as np
from datetime import datetime, timedelta, timezone


def _timestamp_for_hour(hour: int) -> str:
    return (datetime(2026, 6, 20, tzinfo=timezone.utc) + timedelta(hours=hour)).isoformat().replace('+00:00', 'Z')


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

    @pytest.mark.parametrize("reading", [
        {"cpu_percent": 10, "memory_percent": 20},
        {"cpu_percent": float("nan"), "memory_percent": 20, "disk_percent": 30},
        {"cpu_percent": float("inf"), "memory_percent": 20, "disk_percent": 30},
        {"cpu_percent": -1, "memory_percent": 20, "disk_percent": 30},
        {"cpu_percent": 10, "memory_percent": 20, "disk_percent": 101},
        {"cpu_percent": True, "memory_percent": 20, "disk_percent": 30},
    ])
    def test_predictor_rejects_incomplete_or_invalid_telemetry(self, reading):
        from resilience.predictor import ResiliencePredictor
        with pytest.raises(ValueError):
            ResiliencePredictor._extract_features(reading)

    def test_predictor_rejects_invalid_configuration(self):
        from resilience.predictor import ResiliencePredictor
        with pytest.raises(ValueError):
            ResiliencePredictor(contamination=0.0)
        with pytest.raises(ValueError):
            ResiliencePredictor(contamination=0.9)
        with pytest.raises(ValueError):
            ResiliencePredictor(n_estimators=0)

    def test_model_load_requires_trusted_digest_and_rejects_tampering(self):
        import tempfile, os
        from resilience.predictor import ResiliencePredictor
        predictor = ResiliencePredictor()
        data = [{"cpu_percent": 20 + i, "memory_percent": 30, "disk_percent": 40} for i in range(15)]
        predictor.train(data)
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            path = f.name
        try:
            digest = predictor.save(path)
            with pytest.raises(ValueError, match="trusted 64-character"):
                ResiliencePredictor.load(path)
            with open(path, "ab") as f:
                f.write(b"tampered")
            with pytest.raises(ValueError, match="SHA-256"):
                ResiliencePredictor.load(path, expected_sha256=digest)
        finally:
            os.unlink(path)

    def test_model_can_be_serialised_and_loaded(self):
        import tempfile, os
        from resilience.predictor import ResiliencePredictor
        predictor = ResiliencePredictor()
        data = [{"cpu_percent": 20 + i, "memory_percent": 30, "disk_percent": 40} for i in range(15)]
        predictor.train(data)
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            path = f.name
        try:
            expected_sha256 = predictor.save(path)
            loaded = ResiliencePredictor.load(path, expected_sha256=expected_sha256)
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
            {"timestamp": _timestamp_for_hour(10 + i),
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
            {"timestamp": _timestamp_for_hour(i),
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
            {"timestamp": _timestamp_for_hour(i),
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
            {"timestamp": _timestamp_for_hour(i),
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
            {"timestamp": _timestamp_for_hour(i),
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
                {"timestamp": _timestamp_for_hour(i),
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
        from datetime import datetime, timezone
        from core.database import AsyncSessionLocal
        from models.device import Device
        async with AsyncSessionLocal() as db:
            if await db.get(Device, "srv-002") is None:
                db.add(Device(
                    id="srv-002", org_id="test-tenant", name="srv-002",
                    is_active=True, enrolled_at=datetime.now(timezone.utc),
                ))
                await db.commit()
        r = await client.post("/devices/telemetry", json={
            "device_id": "srv-002",
            "cpu_percent": 30.0,
            "memory_percent": 45.0,
            "disk_percent": 60.0,
        })
        assert r.status_code == 200
        data = r.json()
        assert data["resilience"]["score"] >= 60
