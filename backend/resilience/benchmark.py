"""Reproducible offline evaluation for resilience heuristics.

Reports are descriptive evaluation artifacts, not production certification. Callers must
supply a genuinely held-out dataset and state its label source and split strategy.
"""
from __future__ import annotations

import hashlib
import json
import math
from numbers import Real
from typing import Any

from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from resilience.predictor import ResiliencePredictor
from resilience.temporal import TemporalCorrelator


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> list[float]:
    if trials <= 0:
        raise ValueError("Wilson interval requires at least one trial.")
    p = successes / trials
    denominator = 1.0 + z * z / trials
    center = (p + z * z / (2.0 * trials)) / denominator
    margin = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * trials)) / trials) / denominator
    return [round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)]


def _classification_summary(labels: list[int], predictions: list[int], scores: list[float]) -> dict:
    tn, fp, fn, tp = (
        int(value)
        for value in confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    )
    negative_count = tn + fp
    positive_count = tp + fn
    return {
        "accuracy": round(float(accuracy_score(labels, predictions)), 6),
        "precision": round(float(precision_score(labels, predictions, zero_division=0)), 6),
        "recall": round(float(recall_score(labels, predictions, zero_division=0)), 6),
        "f1": round(float(f1_score(labels, predictions, zero_division=0)), 6),
        "false_positive_rate": round(fp / negative_count, 6),
        "false_positive_rate_ci95_wilson": _wilson_interval(fp, negative_count),
        "false_negative_rate": round(fn / positive_count, 6),
        "average_precision": round(float(average_precision_score(labels, scores)), 6),
        "roc_auc": round(float(roc_auc_score(labels, scores)), 6),
        "confusion_matrix": {
            "true_negative": tn, "false_positive": fp,
            "false_negative": fn, "true_positive": tp,
        },
    }


def evaluate_anomaly_detector(
    training_baseline: list[dict],
    evaluation_samples: list[dict],
    labels: list[int | bool],
    *,
    label_source: str,
    split_strategy: str,
    contamination: float = 0.05,
    n_estimators: int = 100,
) -> dict:
    """Train on a baseline set and evaluate on separate, labeled holdout samples."""
    if not isinstance(training_baseline, list) or len(training_baseline) < 5:
        raise ValueError("training_baseline must contain at least five valid baseline samples.")
    if not isinstance(label_source, str) or not label_source.strip():
        raise ValueError("label_source is required for evaluation provenance.")
    if not isinstance(split_strategy, str) or not split_strategy.strip():
        raise ValueError("split_strategy is required for evaluation provenance.")
    if not isinstance(evaluation_samples, list) or not evaluation_samples:
        raise ValueError("evaluation_samples must contain at least one sample.")
    if not isinstance(labels, list) or len(labels) != len(evaluation_samples):
        raise ValueError("labels length must equal evaluation_samples length.")
    normalized_labels: list[int] = []
    for label in labels:
        if label not in (0, 1, False, True):
            raise ValueError("Anomaly labels must be binary 0/1.")
        normalized_labels.append(int(label))
    if set(normalized_labels) != {0, 1}:
        raise ValueError("Holdout evaluation must include both normal and anomalous labels.")

    # Validate all feature vectors before fitting/evaluating.
    normalized_train = [ResiliencePredictor._extract_features(item) for item in training_baseline]
    normalized_eval = [ResiliencePredictor._extract_features(item) for item in evaluation_samples]
    train_data = [dict(zip(("cpu_percent", "memory_percent", "disk_percent"), values)) for values in normalized_train]
    eval_data = [dict(zip(("cpu_percent", "memory_percent", "disk_percent"), values)) for values in normalized_eval]

    predictor = ResiliencePredictor(contamination=contamination, n_estimators=n_estimators)
    predictor.train(train_data)
    outputs = [predictor.predict(sample) for sample in eval_data]
    combined_predictions = [int(result["is_anomaly"]) for result in outputs]
    model_predictions = [int(result["model_is_anomaly"]) for result in outputs]
    scores = [float(result["anomaly_score"]) for result in outputs]
    combined_metrics = _classification_summary(normalized_labels, combined_predictions, scores)
    model_only_metrics = _classification_summary(normalized_labels, model_predictions, scores)
    negative_count = sum(label == 0 for label in normalized_labels)
    positive_count = sum(label == 1 for label in normalized_labels)

    train_manifest = {
        "features": train_data,
        "sample_count": len(train_data),
    }
    evaluation_manifest = {
        "samples": [
            {"features": sample, "label": label}
            for sample, label in zip(eval_data, normalized_labels)
        ],
        "sample_count": len(eval_data),
        "label_source": label_source.strip(),
        "split_strategy": split_strategy.strip(),
    }
    return {
        "schema_version": "aurontra.predictive-evaluation.v1",
        "evaluation_type": "offline_holdout",
        "production_validation": False,
        "interpretation": "Descriptive metrics only; not a certification or guarantee of production performance.",
        "model": {
            "type": "isolation_forest",
            "version": 1,
            "contamination": float(contamination),
            "n_estimators": int(n_estimators),
            "random_state": 42,
            "feature_keys": ["cpu_percent", "memory_percent", "disk_percent"],
            "confidence_calibrated": False,
        },
        "dataset": {
            "training_sample_count": len(train_data),
            "evaluation_sample_count": len(eval_data),
            "positive_count": positive_count,
            "negative_count": negative_count,
            "label_source": label_source.strip(),
            "split_strategy": split_strategy.strip(),
            "training_sha256": _canonical_hash(train_manifest),
            "evaluation_sha256": _canonical_hash(evaluation_manifest),
        },
        "metrics": {
            # Backward-compatible top-level fields describe the combined operational decision.
            **combined_metrics,
            "combined_policy": combined_metrics,
            "model_only": model_only_metrics,
        },
    }


def evaluate_temporal_forecasts(cases: list[dict], *, horizon_hours: int = 72) -> dict:
    """Compare heuristic forecasts with observed future scores from a held-out case set."""
    if not isinstance(cases, list) or not cases:
        raise ValueError("At least one temporal evaluation case is required.")
    correlator = TemporalCorrelator(forecast_horizon_hours=horizon_hours)
    predictions: list[float] = []
    actuals: list[float] = []
    manifest_cases: list[dict] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or not isinstance(case.get("series"), list):
            raise ValueError(f"Temporal evaluation case {index} must contain a series.")
        actual = case.get("actual_score")
        if isinstance(actual, bool) or not isinstance(actual, Real) or not math.isfinite(float(actual)) or not 0 <= float(actual) <= 100:
            raise ValueError(f"Temporal evaluation case {index} actual_score must be finite and between 0 and 100.")
        forecast = correlator.analyse(case["series"])
        predictions.append(float(forecast["predicted_score"]))
        actuals.append(float(actual))
        manifest_cases.append({
            "case_id": str(case.get("case_id", index)),
            "series": case["series"],
            "actual_score": float(actual),
        })
    errors = [predicted - actual for predicted, actual in zip(predictions, actuals)]
    absolute_errors = [abs(error) for error in errors]
    mae = sum(absolute_errors) / len(errors)
    rmse = math.sqrt(sum(error * error for error in errors) / len(errors))
    bias = sum(errors) / len(errors)
    return {
        "schema_version": "aurontra.temporal-evaluation.v1",
        "evaluation_type": "offline_holdout",
        "production_validation": False,
        "forecast_type": "linear_trend_heuristic",
        "calibration_status": "not_calibrated",
        "horizon_hours": horizon_hours,
        "case_count": len(cases),
        "dataset_sha256": _canonical_hash(manifest_cases),
        "metrics": {
            "mae_score_points": round(mae, 4),
            "rmse_score_points": round(rmse, 4),
            "mean_bias_score_points": round(bias, 4),
            "within_10_points_rate": round(sum(error <= 10 for error in absolute_errors) / len(errors), 6),
            "predictions": [
                {"case_id": manifest_cases[i]["case_id"], "actual_score": actuals[i], "predicted_score": predictions[i], "horizon_hours": horizon_hours, "error": round(errors[i], 4)}
                for i in range(len(cases))
            ],
        },
    }
