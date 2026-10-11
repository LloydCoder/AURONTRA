"""Threat evidence validation and evaluation regression tests."""
import pytest

from core.threat_evidence import evaluate_labeled_dataset, sha256_json, validate_signal, wilson_interval


def test_signal_validation_normalizes_ip_and_protocol():
    result = validate_signal({"src_ip": "192.0.2.1", "protocol": "quic", "entropy": 7.1, "z_score": 4.0})
    assert result["src_ip"] == "192.0.2.1"
    assert result["protocol"] == "QUIC"
    assert result["entropy"] == 7.1


@pytest.mark.parametrize("signal", [
    {"entropy": float("nan")},
    {"entropy": 9},
    {"jitter": -0.1},
    {"z_score": float("inf")},
    {"beacon_interval": 0},
    {"bytes_out": -1},
    {"src_ip": "not-an-ip"},
    {"protocol": "UNKNOWN"},
    {"entropy": True},
    {"unsupported": "value"},
])
def test_signal_validation_rejects_invalid_or_unbounded_values(signal):
    with pytest.raises(ValueError):
        validate_signal(signal)


def test_canonical_hash_is_stable_across_key_order():
    assert sha256_json({"a": 1, "b": 2}) == sha256_json({"b": 2, "a": 1})


def test_labeled_evaluation_reports_confusion_matrix_and_dataset_digest():
    examples = [
        {"id": "1", "label_malicious": True, "score": 90},
        {"id": "2", "label_malicious": True, "score": 20},
        {"id": "3", "label_malicious": False, "score": 80},
        {"id": "4", "label_malicious": False, "score": 10},
    ]
    report = evaluate_labeled_dataset("fixture-v1", examples, threshold=60)
    assert report["dataset_size"] == 4
    assert report["confusion_matrix"] == {
        "true_positive": 1, "false_positive": 1, "true_negative": 1, "false_negative": 1
    }
    assert report["metrics"]["precision"] == 0.5
    assert report["metrics"]["recall"] == 0.5
    assert report["metrics"]["false_positive_rate"] == 0.5
    assert len(report["dataset_sha256"]) == 64
    assert "not a calibrated probability" in " ".join(report["limitations"])


def test_labeled_evaluation_rejects_duplicate_ids_and_invalid_labels():
    with pytest.raises(ValueError):
        evaluate_labeled_dataset("fixture", [
            {"id": "same", "label_malicious": True, "score": 90},
            {"id": "same", "label_malicious": False, "score": 10},
        ])
    with pytest.raises(ValueError):
        evaluate_labeled_dataset("fixture", [{"id": "1", "label_malicious": 1, "score": 90}])


def test_wilson_interval_handles_zero_denominator_and_all_successes():
    assert wilson_interval(0, 0) is None
    interval = wilson_interval(10, 10)
    assert interval is not None
    assert interval[0] < 1.0
    assert interval[1] == 1.0
