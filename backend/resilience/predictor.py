"""
Isolation Forest anomaly detector for device telemetry.

Trained on historical device metrics.
Predicts whether a new reading is anomalous vs baseline.

Design decisions:
- contamination=0.05 → expects ~5% of training data to be anomalous
- n_estimators=100 → stable predictions with moderate compute
- Features: cpu_percent, memory_percent, disk_percent (extensible)
- Serialise/load via pickle for persistence across restarts
"""
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Optional


_FEATURE_KEYS = ["cpu_percent", "memory_percent", "disk_percent"]
_MIN_TRAINING_SAMPLES = 5


class ResiliencePredictor:
    """
    Isolation Forest wrapper for device resilience anomaly detection.

    Usage:
        predictor = ResiliencePredictor()
        predictor.train(telemetry_history)
        result = predictor.predict(current_reading)
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        self._model: Optional[IsolationForest] = None
        self._contamination = contamination
        self._n_estimators = n_estimators
        self.is_trained = False

    def _extract_features(self, reading: dict) -> list[float]:
        """Extract ordered feature vector from a telemetry reading."""
        return [float(reading.get(k, 0.0)) for k in _FEATURE_KEYS]

    def train(self, data: list[dict]) -> None:
        """
        Train the Isolation Forest on historical telemetry.

        Args:
            data: list of telemetry dicts (each with cpu/memory/disk_percent)

        Raises:
            ValueError: if fewer than MIN_TRAINING_SAMPLES provided
        """
        if len(data) < _MIN_TRAINING_SAMPLES:
            raise ValueError(
                f"Need at least {_MIN_TRAINING_SAMPLES} samples to train. "
                f"Got {len(data)}."
            )

        X = np.array([self._extract_features(r) for r in data])
        self._model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=42,
        )
        self._model.fit(X)
        self.is_trained = True

    def predict(self, reading: dict) -> dict:
        """
        Predict whether a telemetry reading is anomalous.

        Args:
            reading: dict with cpu_percent, memory_percent, disk_percent

        Returns:
            dict: is_anomaly (bool), anomaly_score (float), confidence (float)

        Raises:
            RuntimeError: if model has not been trained yet
        """
        if not self.is_trained or self._model is None:
            raise RuntimeError(
                "Model must be trained before calling predict(). "
                "Call train() with historical telemetry first."
            )

        X = np.array([self._extract_features(reading)])

        # Hard threshold override — values >= 95% on any metric are always anomalous
        # regardless of model verdict (training data may lack variance to detect these)
        features = self._extract_features(reading)
        hard_anomaly = any(v >= 95.0 for v in features)

        # IsolationForest: -1 = anomaly, 1 = normal
        prediction = self._model.predict(X)[0]
        raw_score = self._model.score_samples(X)[0]

        # Normalise raw score to 0-1 (higher = more anomalous)
        normalised = float(np.clip(-raw_score, 0, 1))
        confidence = round(min(1.0, abs(normalised) * 2), 3)

        is_anomaly = bool(prediction == -1) or hard_anomaly

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(float(normalised), 4),
            "confidence": confidence,
            "features_used": _FEATURE_KEYS,
        }

    def save(self, path: str) -> None:
        """Serialise the trained model to disk."""
        with open(path, "wb") as f:
            pickle.dump({"model": self._model, "is_trained": self.is_trained}, f)

    @classmethod
    def load(cls, path: str) -> "ResiliencePredictor":
        """Load a previously saved model from disk."""
        instance = cls()
        with open(path, "rb") as f:
            state = pickle.load(f)
        instance._model = state["model"]
        instance.is_trained = state["is_trained"]
        return instance


# Module-level singleton — loaded on first import, shared across requests
_global_predictor: Optional[ResiliencePredictor] = None


def get_predictor() -> ResiliencePredictor:
    """Return the global predictor instance, initialising if needed."""
    global _global_predictor
    if _global_predictor is None:
        _global_predictor = ResiliencePredictor()
    return _global_predictor
