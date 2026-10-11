"""Reproducibility and calibration-contract tests for threat scoring."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from threats.benchmark import evaluate_threat_dataset


DATASET_PATH = Path(__file__).parents[1] / "fixtures" / "threat_detection_benchmark.json"


def _dataset():
    return json.loads(DATASET_PATH.read_text(encoding="utf-8"))


def _canonical_hash(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def test_threat_benchmark_is_deterministic_and_hash_bound():
    dataset = _dataset()
    first = evaluate_threat_dataset(dataset)
    second = evaluate_threat_dataset(dataset)
    assert first["report_sha256"] == second["report_sha256"]
    assert first["dataset"]["dataset_sha256"] == second["dataset"]["dataset_sha256"]
    unsigned = {key: value for key, value in first.items() if key != "report_sha256"}
    assert first["report_sha256"] == _canonical_hash(unsigned)


def test_threat_benchmark_separates_calibration_and_holdout_and_reports_limits():
    report = evaluate_threat_dataset(_dataset())
    assert report["production_validation"] is False
    assert report["calibration"]["status"] == "synthetic_only_not_for_production"
    assert report["detector"]["raw_score_semantics"] == "heuristic_0_to_100_not_probability"
    assert report["dataset"]["calibration_count"] == 16
    assert report["dataset"]["holdout_count"] == 16
    raw = report["metrics"]["raw_score_threshold"]
    calibrated = report["metrics"]["calibrated_probability_threshold"]
    assert sum(raw["confusion_matrix"].values()) == 16
    assert sum(calibrated["confusion_matrix"].values()) == 16
    assert 0 <= calibrated["brier_score"] <= 1
    assert 0 <= calibrated["expected_calibration_error_10_bins"] <= 1
    assert len(raw["false_positive_rate_ci95_wilson"]) == 2
    assert len(raw["false_negative_rate_ci95_wilson"]) == 2


def test_threat_benchmark_rejects_duplicate_ids_and_missing_classes():
    dataset = _dataset()
    duplicate = copy.deepcopy(dataset)
    duplicate["records"][1]["id"] = duplicate["records"][0]["id"]
    with pytest.raises(ValueError, match="unique"):
        evaluate_threat_dataset(duplicate)

    missing_class = copy.deepcopy(dataset)
    for record in missing_class["records"]:
        if record["split"] == "holdout":
            record["label"] = "benign"
    with pytest.raises(ValueError, match="both contain"):
        evaluate_threat_dataset(missing_class)


def test_threat_benchmark_hash_changes_when_signal_changes():
    dataset = _dataset()
    original = evaluate_threat_dataset(dataset)
    modified = copy.deepcopy(dataset)
    modified["records"][0]["signal"]["entropy"] = 2.3
    changed = evaluate_threat_dataset(modified)
    assert original["dataset"]["dataset_sha256"] != changed["dataset"]["dataset_sha256"]
