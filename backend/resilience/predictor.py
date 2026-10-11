"""Validated Isolation Forest anomaly detector.

The score is an uncalibrated anomaly ranking, not a probability or failure forecast.
Model persistence uses pickle only behind an externally trusted SHA-256 allowlist.
"""
from __future__ import annotations

import hashlib
import hmac
import pickle
from numbers import Real
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest


_FEATURE_KEYS = ("cpu_percent", "memory_percent", "disk_percent")
_MIN_TRAINING_SAMPLES = 5


class ResiliencePredictor:
    """Isolation Forest wrapper with strict telemetry validation."""

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        if isinstance(contamination, bool) or not isinstance(contamination, Real):
            raise ValueError("contamination must be numeric in (0, 0.5]")
        if not 0 < float(contamination) <= 0.5:
            raise ValueError("contamination must be in (0, 0.5]")
        if isinstance(n_estimators, bool) or not isinstance(n_estimators, int) or n_estimators < 1:
            raise ValueError("n_estimators must be a positive integer")
        self._model: Optional[IsolationForest] = None
        self._contamination = float(contamination)
        self._n_estimators = n_estimators
        self.is_trained = False

    @staticmethod
    def _extract_features(reading: dict) -> list[float]:
        """Validate and extract all required telemetry metrics; never impute missing values."""
        if not isinstance(reading, dict):
            raise ValueError("telemetry reading must be an object")
        missing = [key for key in _FEATURE_KEYS if key not in reading]
        if missing:
            raise ValueError(f"telemetry reading is missing required metrics: {', '.join(missing)}")
        features: list[float] = []
        for key in _FEATURE_KEYS:
            value = reading[key]
            if isinstance(value, bool) or not isinstance(value, (Real, np.number)):
                raise ValueError(f"{key} must be a numeric percentage")
            number = float(value)
            if not np.isfinite(number) or not 0.0 <= number <= 100.0:
                raise ValueError(f"{key} must be finite and between 0 and 100")
            features.append(number)
        return features

    def train(self, data: list[dict]) -> None:
        """Train on a caller-supplied baseline dataset with at least five valid samples."""
        if not isinstance(data, list) or len(data) < _MIN_TRAINING_SAMPLES:
            count = len(data) if isinstance(data, list) else 0
            raise ValueError(f"Need at least {_MIN_TRAINING_SAMPLES} samples to train. Got {count}.")
        X = np.asarray([self._extract_features(reading) for reading in data], dtype=float)
        model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=42,
        )
        model.fit(X)
        self._model = model
        self.is_trained = True

    def predict(self, reading: dict) -> dict:
        """Return an anomaly label and uncalibrated ranking for a fully observed sample."""
        if not self.is_trained or self._model is None:
            raise RuntimeError("Model must be trained before calling predict().")
        features = self._extract_features(reading)
        X = np.asarray([features], dtype=float)
        prediction = int(self._model.predict(X)[0])
        raw_score = float(self._model.score_samples(X)[0])
        anomaly_score = float(np.clip(-raw_score, 0.0, 1.0))
        hard_anomaly = any(value >= 95.0 for value in features)
        is_anomaly = prediction == -1 or hard_anomaly
        return {
            "is_anomaly": bool(is_anomaly),
            "model_is_anomaly": bool(prediction == -1),
            "anomaly_score": round(anomaly_score, 4),
            # Retained for API compatibility; explicitly not a calibrated probability.
            "confidence": round(min(1.0, anomaly_score * 2.0), 3),
            "confidence_semantics": "uncalibrated_heuristic_not_probability",
            "model_type": "isolation_forest",
            "model_version": 1,
            "features_used": list(_FEATURE_KEYS),
            "hard_threshold_triggered": bool(hard_anomaly),
        }

    def save(self, path: str | Path) -> str:
        """Save a model artifact and return its SHA-256 for a trusted registry to pin."""
        if not self.is_trained or self._model is None:
            raise RuntimeError("Cannot save an untrained model.")
        artifact = pickle.dumps(
            {
                "model": self._model,
                "is_trained": True,
                "model_version": 1,
                "feature_keys": list(_FEATURE_KEYS),
                "contamination": self._contamination,
                "n_estimators": self._n_estimators,
            },
            protocol=pickle.HIGHEST_PROTOCOL,
        )
        Path(path).write_bytes(artifact)
        return hashlib.sha256(artifact).hexdigest()

    @classmethod
    def load(cls, path: str | Path, *, expected_sha256: str | None = None) -> "ResiliencePredictor":
        """Load only when a SHA-256 from a trusted channel pins the exact artifact bytes.

        The expected digest must come from a signed/trusted deployment manifest or model
        registry—not from a sidecar stored beside the model file. Pickle is executable data.
        """
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in expected_sha256)
        ):
            raise ValueError("A trusted 64-character expected_sha256 is required to load model artifacts.")
        artifact = Path(path).read_bytes()
        actual_sha256 = hashlib.sha256(artifact).hexdigest()
        if not hmac.compare_digest(actual_sha256, expected_sha256.lower()):
            raise ValueError("Model artifact SHA-256 does not match the trusted expected digest.")
        # Only deserialise after the trusted digest check.
        state = pickle.loads(artifact)
        if (
            not isinstance(state, dict)
            or state.get("model_version") != 1
            or state.get("feature_keys") != list(_FEATURE_KEYS)
            or state.get("is_trained") is not True
            or not isinstance(state.get("model"), IsolationForest)
            or getattr(state["model"], "n_features_in_", None) != len(_FEATURE_KEYS)
        ):
            raise ValueError("Model artifact schema or model type is invalid.")
        instance = cls(
            contamination=state.get("contamination", 0.05),
            n_estimators=state.get("n_estimators", 100),
        )
        instance._model = state["model"]
        instance.is_trained = True
        return instance


_global_predictor: Optional[ResiliencePredictor] = None


def get_predictor() -> ResiliencePredictor:
    """Return the in-process predictor; production artifacts must be verified before loading."""
    global _global_predictor
    if _global_predictor is None:
        _global_predictor = ResiliencePredictor()
    return _global_predictor
