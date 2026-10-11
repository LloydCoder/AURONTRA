"""Time-aware trend heuristic for telemetry.

This is a transparent linear projection, not a validated or calibrated predictive model.
All slopes are computed per elapsed hour from timezone-aware timestamps.
"""
from __future__ import annotations

from datetime import datetime, timezone
from numbers import Real
from typing import Any

import numpy as np

_FEATURE_KEYS = ("cpu_percent", "memory_percent", "disk_percent")
_MIN_SERIES_LENGTH = 2
_TREND_WINDOW = 5
_RISE_THRESHOLD = 2.0
_DISK_RISK_THRESHOLD = 3.0


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Every telemetry reading requires an ISO-8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Telemetry timestamps must be valid ISO-8601 values.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Telemetry timestamps must include a timezone.")
    return parsed.astimezone(timezone.utc)


def _validate_series(series: list[dict]) -> tuple[list[datetime], dict[str, list[float]]]:
    if not isinstance(series, list):
        raise ValueError("Series must be a list of telemetry readings.")
    timestamps: list[datetime] = []
    values: dict[str, list[float]] = {key: [] for key in _FEATURE_KEYS}
    for index, reading in enumerate(series):
        if not isinstance(reading, dict):
            raise ValueError(f"Telemetry reading {index} must be an object.")
        timestamps.append(_parse_timestamp(reading.get("timestamp")))
        for key in _FEATURE_KEYS:
            if key not in reading:
                raise ValueError(f"Telemetry reading {index} is missing {key}.")
            value = reading[key]
            if isinstance(value, bool) or not isinstance(value, Real):
                raise ValueError(f"{key} must be a numeric percentage.")
            number = float(value)
            if not np.isfinite(number) or not 0.0 <= number <= 100.0:
                raise ValueError(f"{key} must be finite and between 0 and 100.")
            values[key].append(number)
    for previous, current in zip(timestamps, timestamps[1:]):
        if current <= previous:
            raise ValueError("Telemetry timestamps must be strictly increasing.")
    return timestamps, values


def _linear_slope(values: list[float], elapsed_hours: list[float] | None = None) -> float:
    """Compute least-squares slope per hour; default x-values are hourly sample indices."""
    if len(values) < 2:
        return 0.0
    x = np.asarray(elapsed_hours if elapsed_hours is not None else range(len(values)), dtype=float)
    y = np.asarray(values, dtype=float)
    if len(x) != len(y) or not np.isfinite(x).all() or not np.isfinite(y).all():
        raise ValueError("Slope input must contain finite, equally sized arrays.")
    if np.ptp(x) <= 0:
        raise ValueError("Slope timestamps must span a positive duration.")
    return float(np.polyfit(x, y, 1)[0])


def _extract_metric(series: list[dict], key: str) -> list[float]:
    """Extract a required metric; missing readings are never silently replaced with zero."""
    if key not in _FEATURE_KEYS:
        raise ValueError(f"Unsupported telemetry metric: {key}")
    values: list[float] = []
    for index, reading in enumerate(series):
        if key not in reading:
            raise ValueError(f"Telemetry reading {index} is missing {key}.")
        value = reading[key]
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError(f"{key} must be numeric.")
        number = float(value)
        if not np.isfinite(number) or not 0.0 <= number <= 100.0:
            raise ValueError(f"{key} must be finite and between 0 and 100.")
        values.append(number)
    return values


class TemporalCorrelator:
    """Compute a transparent, time-aware 72-hour trend projection."""

    def __init__(self, forecast_horizon_hours: int = 72):
        if isinstance(forecast_horizon_hours, bool) or not isinstance(forecast_horizon_hours, int) or forecast_horizon_hours < 1 or forecast_horizon_hours > 720:
            raise ValueError("forecast_horizon_hours must be an integer between 1 and 720")
        self.forecast_horizon_hours = forecast_horizon_hours

    def analyse(self, series: list[dict]) -> dict:
        """Analyze complete, ordered, timestamped readings and return an unvalidated heuristic forecast."""
        if not series:
            raise ValueError("Series cannot be empty.")
        if len(series) < _MIN_SERIES_LENGTH:
            raise ValueError(f"Need at least {_MIN_SERIES_LENGTH} readings for trend analysis. Got {len(series)}.")

        timestamps, metrics = _validate_series(series)
        start = timestamps[0]
        elapsed_hours = [(timestamp - start).total_seconds() / 3600.0 for timestamp in timestamps]
        window_start = max(0, len(series) - _TREND_WINDOW)
        window_hours = elapsed_hours[window_start:]
        cpu_vals = metrics["cpu_percent"]
        memory_vals = metrics["memory_percent"]
        disk_vals = metrics["disk_percent"]
        cpu_slope = _linear_slope(cpu_vals[window_start:], window_hours)
        memory_slope = _linear_slope(memory_vals[window_start:], window_hours)
        disk_slope = _linear_slope(disk_vals[window_start:], window_hours)

        latest_cpu = cpu_vals[-1]
        latest_memory = memory_vals[-1]
        latest_disk = disk_vals[-1]
        from resilience.scorer import _metric_to_score

        cpu_score = _metric_to_score(latest_cpu, 50, 80)
        memory_score = _metric_to_score(latest_memory, 60, 85)
        disk_score = _metric_to_score(latest_disk, 65, 85)
        weights = {"cpu": 0.25, "memory": 0.25, "disk": 0.5}
        current_score = int(
            cpu_score * weights["cpu"]
            + memory_score * weights["memory"]
            + disk_score * weights["disk"]
        )
        if disk_score <= 20:
            current_score = min(current_score, 59)

        average_slope = (cpu_slope + memory_slope + disk_slope) / 3.0
        if average_slope > _RISE_THRESHOLD:
            trend = "degrading"
        elif average_slope > 0.5:
            trend = "rising"
        elif average_slope < -0.5:
            trend = "improving"
        else:
            trend = "stable"

        horizon = float(self.forecast_horizon_hours)
        projected_cpu = float(np.clip(latest_cpu + cpu_slope * horizon, 0.0, 100.0))
        projected_memory = float(np.clip(latest_memory + memory_slope * horizon, 0.0, 100.0))
        projected_disk = float(np.clip(latest_disk + disk_slope * horizon, 0.0, 100.0))
        projected_cpu_score = _metric_to_score(projected_cpu, 50, 80)
        projected_memory_score = _metric_to_score(projected_memory, 60, 85)
        projected_disk_score = _metric_to_score(projected_disk, 65, 85)
        predicted_score = int(
            projected_cpu_score * weights["cpu"]
            + projected_memory_score * weights["memory"]
            + projected_disk_score * weights["disk"]
        )
        if projected_disk_score <= 20:
            predicted_score = min(predicted_score, 59)
        predicted_score = max(0, min(100, predicted_score))

        risk_factors: list[str] = []
        if cpu_slope > _RISE_THRESHOLD:
            risk_factors.append(f"CPU usage trending up {cpu_slope:.1f} percentage points/hour — possible runaway process")
        if memory_slope > _RISE_THRESHOLD:
            risk_factors.append(f"Memory usage trending up {memory_slope:.1f} percentage points/hour — possible memory leak")
        if disk_slope > _DISK_RISK_THRESHOLD:
            hours_to_full = max(0, int((100.0 - latest_disk) / disk_slope))
            risk_factors.append(f"Disk usage growing {disk_slope:.1f} percentage points/hour — linear estimate {hours_to_full}h to full")
        if max(cpu_vals) - min(cpu_vals) > 40:
            risk_factors.append("High CPU variance — possible intermittent spike")
        if latest_disk > 85:
            risk_factors.append("Disk above 85% — approaching critical threshold")
        if latest_memory > 85:
            risk_factors.append("Memory above 85% — approaching critical threshold")

        result = {
            "trend": trend,
            "predicted_score": predicted_score,
            "current_score": current_score,
            "risk_factors": risk_factors,
            "slopes": {
                "cpu": round(cpu_slope, 3),
                "memory": round(memory_slope, 3),
                "disk": round(disk_slope, 3),
            },
            "readings_analysed": len(series),
            "data_span_hours": round(elapsed_hours[-1], 3),
            "forecast_horizon_hours": self.forecast_horizon_hours,
            "forecast_type": "linear_trend_heuristic",
            "calibration_status": "not_calibrated",
            "production_validation": False,
        }
        # Preserve the legacy field only when it is semantically correct.
        if self.forecast_horizon_hours == 72:
            result["predicted_score_72h"] = predicted_score
        return result
