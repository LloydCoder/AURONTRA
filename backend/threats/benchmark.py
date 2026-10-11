"""Reproducible calibration and holdout evaluation for threat heuristics.

Synthetic fixtures validate the evaluation pipeline only. They do not represent
production traffic and must never be used to claim production detection quality.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from agents.threat_blocker import analyse_signal

SCHEMA_VERSION = "aurontra.threat-detection-evaluation.v1"
RAW_RECOMMENDATION_THRESHOLD = 65
PROBABILITY_THRESHOLD = 0.5


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


def _expected_calibration_error(labels: list[int], probabilities: list[float], bins: int = 10) -> float:
    total = len(labels)
    error = 0.0
    for index in range(bins):
        lower = index / bins
        upper = (index + 1) / bins
        members = [
            i for i, probability in enumerate(probabilities)
            if lower <= probability < upper or (index == bins - 1 and probability == 1.0)
        ]
        if not members:
            continue
        mean_probability = sum(probabilities[i] for i in members) / len(members)
        observed_rate = sum(labels[i] for i in members) / len(members)
        error += (len(members) / total) * abs(mean_probability - observed_rate)
    return error


def _metrics(labels: list[int], scores: list[float], predictions: list[int], probabilities: list[float] | None = None) -> dict:
    tn, fp, fn, tp = (
        int(value) for value in confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    )
    negatives = tn + fp
    positives = tp + fn
    result = {
        "accuracy": round(float(accuracy_score(labels, predictions)), 6),
        "precision": round(float(precision_score(labels, predictions, zero_division=0)), 6),
        "recall": round(float(recall_score(labels, predictions, zero_division=0)), 6),
        "f1": round(float(f1_score(labels, predictions, zero_division=0)), 6),
        "false_positive_rate": round(fp / negatives, 6),
        "false_positive_rate_ci95_wilson": _wilson_interval(fp, negatives),
        "false_negative_rate": round(fn / positives, 6),
        "false_negative_rate_ci95_wilson": _wilson_interval(fn, positives),
        "average_precision": round(float(average_precision_score(labels, scores)), 6),
        "roc_auc": round(float(roc_auc_score(labels, scores)), 6),
        "confusion_matrix": {
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp,
        },
    }
    if probabilities is not None:
        result["brier_score"] = round(
            sum((probability - label) ** 2 for probability, label in zip(probabilities, labels)) / len(labels),
            6,
        )
        result["expected_calibration_error_10_bins"] = round(
            _expected_calibration_error(labels, probabilities, bins=10), 6
        )
    return result


def evaluate_threat_dataset(dataset: dict) -> dict:
    """Fit a calibration layer on a declared calibration split and evaluate on holdout."""
    if not isinstance(dataset, dict) or dataset.get("schema_version") != "aurontra.threat-benchmark.v1":
        raise ValueError("Unsupported threat benchmark schema.")
    label_source = dataset.get("label_source")
    split_strategy = dataset.get("split_strategy")
    if not isinstance(label_source, str) or not label_source.strip():
        raise ValueError("label_source is required.")
    if not isinstance(split_strategy, str) or not split_strategy.strip():
        raise ValueError("split_strategy is required.")
    records = dataset.get("records")
    if not isinstance(records, list) or len(records) < 12:
        raise ValueError("At least twelve labeled records are required.")

    identifiers: set[str] = set()
    normalized: list[dict] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"Record {index} must be an object.")
        record_id = record.get("id")
        if not isinstance(record_id, str) or not record_id.strip() or record_id in identifiers:
            raise ValueError("Record IDs must be non-empty and unique.")
        identifiers.add(record_id)
        label = record.get("label")
        if label not in {"benign", "malicious"}:
            raise ValueError(f"Record {record_id} has an invalid label.")
        split = record.get("split")
        if split not in {"calibration", "holdout"}:
            raise ValueError(f"Record {record_id} must use calibration or holdout split.")
        signal = record.get("signal")
        if not isinstance(signal, dict):
            raise ValueError(f"Record {record_id} must contain a signal object.")
        assessment = analyse_signal(signal)
        normalized.append({
            "id": record_id,
            "label": 1 if label == "malicious" else 0,
            "split": split,
            "signal": signal,
            "score": float(assessment["score"]),
            "threat_level": assessment["threat_level"],
        })

    calibration = [record for record in normalized if record["split"] == "calibration"]
    holdout = [record for record in normalized if record["split"] == "holdout"]
    if len(calibration) < 6 or len(holdout) < 6:
        raise ValueError("Calibration and holdout splits must each contain at least six records.")
    calibration_labels = [record["label"] for record in calibration]
    holdout_labels = [record["label"] for record in holdout]
    if set(calibration_labels) != {0, 1} or set(holdout_labels) != {0, 1}:
        raise ValueError("Both splits must contain benign and malicious labels.")

    calibrator = LogisticRegression(random_state=42, solver="lbfgs", max_iter=1000)
    calibrator.fit([[record["score"]] for record in calibration], calibration_labels)
    holdout_scores = [record["score"] for record in holdout]
    holdout_probabilities = [
        float(value) for value in calibrator.predict_proba([[score] for score in holdout_scores])[:, 1]
    ]
    raw_predictions = [int(score >= RAW_RECOMMENDATION_THRESHOLD) for score in holdout_scores]
    calibrated_predictions = [int(probability >= PROBABILITY_THRESHOLD) for probability in holdout_probabilities]

    dataset_manifest = {
        "schema_version": dataset["schema_version"],
        "dataset_kind": dataset.get("dataset_kind", "unspecified"),
        "label_source": label_source.strip(),
        "split_strategy": split_strategy.strip(),
        "records": [
            {"id": record["id"], "label": record["label"], "split": record["split"], "signal": record["signal"]}
            for record in normalized
        ],
    }
    calibration_manifest = [
        {"id": record["id"], "label": record["label"], "score": record["score"], "signal": record["signal"]}
        for record in calibration
    ]
    holdout_manifest = [
        {"id": record["id"], "label": record["label"], "score": record["score"], "signal": record["signal"]}
        for record in holdout
    ]
    report = {
        "schema_version": SCHEMA_VERSION,
        "evaluation_type": "calibration_then_held_out_evaluation",
        "production_validation": False,
        "interpretation": (
            "Synthetic benchmark only. Metrics verify the evaluation pipeline and do not estimate "
            "real-world false-positive or detection rates."
        ),
        "dataset": {
            "kind": dataset.get("dataset_kind", "unspecified"),
            "record_count": len(normalized),
            "calibration_count": len(calibration),
            "holdout_count": len(holdout),
            "label_source": label_source.strip(),
            "split_strategy": split_strategy.strip(),
            "dataset_sha256": _canonical_hash(dataset_manifest),
            "calibration_sha256": _canonical_hash(calibration_manifest),
            "holdout_sha256": _canonical_hash(holdout_manifest),
        },
        "detector": {
            "name": "heuristic-threat-score",
            "version": "heuristic-threat-score.v2",
            "raw_score_semantics": "heuristic_0_to_100_not_probability",
            "raw_recommendation_threshold": RAW_RECOMMENDATION_THRESHOLD,
            "score_components": ["z_score_points", "entropy_points", "protocol_risk_points", "periodicity_points"],
        },
        "calibration": {
            "method": "logistic_regression_on_raw_score",
            "version": "synthetic-calibration.v1",
            "status": "synthetic_only_not_for_production",
            "calibration_record_count": len(calibration),
            "feature": "raw_heuristic_score_only",
            "coefficient": round(float(calibrator.coef_[0][0]), 8),
            "intercept": round(float(calibrator.intercept_[0]), 8),
            "probability_threshold": PROBABILITY_THRESHOLD,
        },
        "metrics": {
            "raw_score_threshold": _metrics(
                holdout_labels,
                holdout_scores,
                raw_predictions,
            ),
            "calibrated_probability_threshold": _metrics(
                holdout_labels,
                holdout_probabilities,
                calibrated_predictions,
                holdout_probabilities,
            ),
        },
        "holdout_cases": [
            {
                "id": record["id"],
                "label": "malicious" if record["label"] else "benign",
                "raw_score": record["score"],
                "calibrated_probability": round(holdout_probabilities[index], 6),
                "threat_level": record["threat_level"],
            }
            for index, record in enumerate(holdout)
        ],
    }
    report["report_sha256"] = _canonical_hash(report)
    return report
