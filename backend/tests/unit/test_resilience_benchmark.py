"""Offline evaluation contract tests; all fixtures are synthetic, not production telemetry."""
from datetime import datetime, timedelta, timezone

import pytest

from resilience.benchmark import evaluate_anomaly_detector, evaluate_temporal_forecasts
from resilience.temporal import TemporalCorrelator


def _timestamp(hour: int) -> str:
    return (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(hours=hour)).isoformat().replace("+00:00", "Z")


def _reading(cpu: float, memory: float = 40.0, disk: float = 50.0) -> dict:
    return {"cpu_percent": cpu, "memory_percent": memory, "disk_percent": disk}


def _series(cpus: list[float], hours: list[int] | None = None) -> list[dict]:
    hours = hours or list(range(len(cpus)))
    return [
        {"timestamp": _timestamp(hour), **_reading(cpu)}
        for hour, cpu in zip(hours, cpus)
    ]


def test_anomaly_benchmark_is_reproducible_and_explicitly_non_production():
    training = [_reading(20 + (i % 5), 30 + (i % 4), 40 + (i % 3)) for i in range(30)]
    evaluation = [
        _reading(22, 31, 41),
        _reading(24, 32, 42),
        _reading(19, 34, 43),
        _reading(97, 40, 50),
        _reading(35, 98, 52),
        _reading(40, 45, 99),
    ]
    labels = [0, 0, 0, 1, 1, 1]
    report = evaluate_anomaly_detector(
        training,
        evaluation,
        labels,
        label_source="synthetic CI fixture v1",
        split_strategy="separate deterministic synthetic holdout",
    )
    assert report["schema_version"] == "aurontra.predictive-evaluation.v1"
    assert report["production_validation"] is False
    assert report["dataset"]["training_sample_count"] == 30
    assert report["dataset"]["evaluation_sample_count"] == 6
    assert len(report["dataset"]["training_sha256"]) == 64
    assert len(report["dataset"]["evaluation_sha256"]) == 64
    assert 0 <= report["metrics"]["false_positive_rate"] <= 1
    assert len(report["metrics"]["false_positive_rate_ci95_wilson"]) == 2
    assert "model_only" in report["metrics"]
    assert "combined_policy" in report["metrics"]
    assert set(report["metrics"]["confusion_matrix"]) == {
        "true_negative", "false_positive", "false_negative", "true_positive"
    }


def test_anomaly_benchmark_requires_provenance_and_both_classes():
    training = [_reading(20 + i, 30, 40) for i in range(10)]
    evaluation = [_reading(22, 30, 40), _reading(98, 30, 40)]
    with pytest.raises(ValueError, match="label_source"):
        evaluate_anomaly_detector(training, evaluation, [0, 1], label_source="", split_strategy="holdout")
    with pytest.raises(ValueError, match="both normal and anomalous"):
        evaluate_anomaly_detector(
            training, evaluation, [0, 0],
            label_source="manual labels", split_strategy="holdout",
        )


def test_custom_horizon_is_not_mislabeled_as_72_hours():
    result = TemporalCorrelator(forecast_horizon_hours=24).analyse(_series([20, 22, 24]))
    assert "predicted_score" in result
    assert result["forecast_horizon_hours"] == 24
    assert "predicted_score_72h" not in result


def test_anomaly_benchmark_reports_model_and_policy_override_separately(monkeypatch):
    from resilience.predictor import ResiliencePredictor

    def fake_predict(self, reading):
        return {
            "is_anomaly": reading["cpu_percent"] >= 95,
            "model_is_anomaly": False,
            "anomaly_score": reading["cpu_percent"] / 100,
            "confidence": 0.0,
            "confidence_semantics": "uncalibrated_heuristic_not_probability",
        }

    monkeypatch.setattr(ResiliencePredictor, "predict", fake_predict)
    report = evaluate_anomaly_detector(
        [_reading(20 + i, 30, 40) for i in range(10)],
        [_reading(20), _reading(98)],
        [0, 1],
        label_source="synthetic unit test",
        split_strategy="fixed holdout",
    )
    assert report["metrics"]["combined_policy"]["confusion_matrix"]["true_positive"] == 1
    assert report["metrics"]["model_only"]["confusion_matrix"]["true_positive"] == 0


def test_temporal_correlator_uses_elapsed_time_not_sample_index():
    series = _series([20, 30, 40], [0, 2, 4])
    result = TemporalCorrelator().analyse(series)
    assert result["slopes"]["cpu"] == 5.0
    assert result["data_span_hours"] == 4.0
    assert result["forecast_horizon_hours"] == 72
    assert result["calibration_status"] == "not_calibrated"
    assert result["production_validation"] is False


@pytest.mark.parametrize("series", [
    [{"timestamp": _timestamp(0), "cpu_percent": 20, "memory_percent": 30, "disk_percent": 40},
     {"timestamp": _timestamp(1), "cpu_percent": 21, "disk_percent": 41}],
    [{"timestamp": "2026-01-01T00:00:00", **_reading(20)},
     {"timestamp": _timestamp(1), **_reading(21)}],
    [{"timestamp": _timestamp(1), **_reading(20)},
     {"timestamp": _timestamp(0), **_reading(21)}],
    [{"timestamp": _timestamp(0), **_reading(float("nan"))},
     {"timestamp": _timestamp(1), **_reading(21)}],
])
def test_temporal_correlator_rejects_missing_or_invalid_time_series(series):
    with pytest.raises(ValueError):
        TemporalCorrelator().analyse(series)


def test_temporal_forecast_evaluation_reports_error_and_data_provenance():
    cases = [
        {"case_id": "case-a", "series": _series([20, 22, 24]), "actual_score": 88},
        {"case_id": "case-b", "series": _series([30, 40, 50]), "actual_score": 55},
    ]
    report = evaluate_temporal_forecasts(cases)
    assert report["evaluation_type"] == "offline_holdout"
    assert report["production_validation"] is False
    assert report["case_count"] == 2
    assert len(report["dataset_sha256"]) == 64
    assert report["metrics"]["mae_score_points"] >= 0
    assert report["metrics"]["rmse_score_points"] >= 0
    assert len(report["metrics"]["predictions"]) == 2


def test_temporal_evaluation_rejects_invalid_actual_score():
    with pytest.raises(ValueError, match="actual_score"):
        evaluate_temporal_forecasts([{"series": _series([20, 22]), "actual_score": 101}])
