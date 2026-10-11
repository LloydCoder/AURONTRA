"""Validation, provenance, and reproducible offline evaluation for threat signals.

Risk scores are deterministic heuristic outputs, not calibrated probabilities.
The evaluation helper reports performance only for the supplied labelled dataset.
"""
from __future__ import annotations
import hashlib, ipaddress, json, math
from datetime import datetime, timezone
from typing import Any

DETECTOR_VERSION = "threat-heuristic.v2"
_ALLOWED_PROTOCOLS = {"", "DNS", "HTTP", "HTTPS", "ICMP", "QUIC", "RDP", "SMB", "SSH", "TCP", "TLS", "UDP"}
_NUMERIC_FIELDS = {"entropy", "z_score", "beacon_interval", "jitter", "bytes_out"}

def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()

def validate_signal(signal: dict[str, Any]) -> dict[str, Any]:
    """Validate untrusted signal fields and return a normalized bounded copy."""
    if not isinstance(signal, dict) or not signal:
        raise ValueError("Signal must be a non-empty object.")
    allowed = {"src_ip", "protocol", *_NUMERIC_FIELDS}
    if set(signal) - allowed:
        raise ValueError("Signal contains unsupported fields.")
    normalized: dict[str, Any] = {}
    if signal.get("src_ip") is not None:
        if not isinstance(signal["src_ip"], str) or len(signal["src_ip"]) > 64:
            raise ValueError("src_ip must be a valid IP address.")
        try: normalized["src_ip"] = str(ipaddress.ip_address(signal["src_ip"]))
        except ValueError as exc: raise ValueError("src_ip must be a valid IP address.") from exc
    if signal.get("protocol") is not None:
        if not isinstance(signal["protocol"], str): raise ValueError("protocol must be a string.")
        protocol = signal["protocol"].strip().upper()
        if protocol not in _ALLOWED_PROTOCOLS: raise ValueError("protocol is not in the supported protocol vocabulary.")
        normalized["protocol"] = protocol
    for key in _NUMERIC_FIELDS:
        if key not in signal or signal[key] is None: continue
        value = signal[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise ValueError(f"{key} must be a finite number.")
        number = float(value)
        if key == "entropy" and not 0 <= number <= 8: raise ValueError("entropy must be between 0 and 8.")
        if key == "z_score" and not -1000 <= number <= 1000: raise ValueError("z_score must be between -1000 and 1000.")
        if key == "beacon_interval" and (not number.is_integer() or not 1 <= number <= 86400): raise ValueError("beacon_interval must be an integer between 1 and 86400 seconds.")
        if key == "jitter" and not 0 <= number <= 1: raise ValueError("jitter must be between 0 and 1.")
        if key == "bytes_out" and (not number.is_integer() or not 0 <= number <= 2**63 - 1): raise ValueError("bytes_out must be a non-negative integer.")
        normalized[key] = int(number) if key in {"beacon_interval", "bytes_out"} else number
    if not normalized: raise ValueError("Signal must contain at least one supported field.")
    return normalized

def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> list[float] | None:
    """Two-sided 95% Wilson score interval; returns None when denominator is zero."""
    if trials <= 0: return None
    if successes < 0 or successes > trials: raise ValueError("successes must be between zero and trials.")
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    radius = z * math.sqrt((p * (1 - p) / trials) + (z * z / (4 * trials * trials))) / denominator
    return [max(0.0, center - radius), min(1.0, center + radius)]

def evaluate_labeled_dataset(dataset_id: str, examples: list[dict[str, Any]], threshold: int = 60) -> dict[str, Any]:
    """Compute reproducible confusion-matrix metrics on labelled score examples.

    Each example requires a unique stable id, boolean ground-truth label, and integer
    score in [0,100]. This does not calibrate the score or generalize beyond this dataset.
    """
    if not isinstance(dataset_id, str) or not dataset_id.strip() or len(dataset_id) > 128:
        raise ValueError("dataset_id must be a non-empty string up to 128 characters.")
    if not isinstance(examples, list) or not examples or len(examples) > 1_000_000:
        raise ValueError("examples must contain between 1 and 1,000,000 labelled records.")
    if isinstance(threshold, bool) or not isinstance(threshold, int) or not 0 <= threshold <= 100:
        raise ValueError("threshold must be an integer between 0 and 100.")
    seen: set[str] = set(); tp = fp = tn = fn = 0; normalized = []
    for index, example in enumerate(examples):
        if not isinstance(example, dict): raise ValueError(f"example {index} must be an object.")
        identifier, label, score = example.get("id"), example.get("label_malicious"), example.get("score")
        if not isinstance(identifier, str) or not identifier or len(identifier) > 128 or identifier in seen:
            raise ValueError("each example requires a unique non-empty id.")
        if not isinstance(label, bool): raise ValueError("label_malicious must be a boolean ground-truth label.")
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            raise ValueError("score must be an integer between 0 and 100.")
        seen.add(identifier); predicted = score >= threshold
        if predicted and label: tp += 1
        elif predicted and not label: fp += 1
        elif not predicted and label: fn += 1
        else: tn += 1
        normalized.append({"id": identifier, "label_malicious": label, "score": score})
    positives, negatives, predicted_positives = tp + fn, tn + fp, tp + fp
    metrics = {
        "precision": tp / predicted_positives if predicted_positives else None,
        "recall": tp / positives if positives else None,
        "false_positive_rate": fp / negatives if negatives else None,
        "false_negative_rate": fn / positives if positives else None,
        "accuracy": (tp + tn) / len(normalized),
        "precision_95ci_wilson": wilson_interval(tp, predicted_positives),
        "recall_95ci_wilson": wilson_interval(tp, positives),
        "false_positive_rate_95ci_wilson": wilson_interval(fp, negatives),
    }
    return {
        "dataset_id": dataset_id, "dataset_sha256": sha256_json(normalized),
        "dataset_size": len(normalized), "threshold": threshold, "detector_version": DETECTOR_VERSION,
        "metrics": metrics, "confusion_matrix": {"true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn},
        "confidence_semantics": "frequentist_Wilson_95_percent_interval_for_observed_proportions",
        "limitations": [
            "Metrics apply only to the exact labelled dataset hash and threshold.",
            "The risk score is a heuristic and is not a calibrated probability.",
            "Dataset representativeness, label quality, temporal leakage, and deployment drift require independent review.",
            "This report does not prove real-world detection or containment.",
        ],
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
