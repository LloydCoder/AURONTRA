"""
Temporal Correlator — time-series trend analysis for resilience prediction.

Analyses a sequence of telemetry readings to:
  1. Identify current trend (stable / rising / degrading)
  2. Project 72-hour future resilience score
  3. Flag specific risk factors (disk growth, memory leak pattern, CPU spike trend)

Inspired by ReconOS OFE's TemporalCorrelator — adapted for IT resilience metrics
rather than OSINT event streams.
"""
import numpy as np
from typing import Any
from resilience.scorer import score_device, score_to_status


_MIN_SERIES_LENGTH = 2
_TREND_WINDOW = 5          # readings for trend calculation
_RISE_THRESHOLD = 2.0      # avg increase per reading to flag as "rising"
_DISK_RISK_THRESHOLD = 3.0 # disk growth per reading to flag as risk


def _linear_slope(values: list[float]) -> float:
    """Compute slope of a linear regression through the values."""
    if len(values) < 2:
        return 0.0
    x = np.arange(len(values), dtype=float)
    y = np.array(values, dtype=float)
    # Least-squares slope
    slope = float(np.polyfit(x, y, 1)[0])
    return slope


def _extract_metric(series: list[dict], key: str) -> list[float]:
    """Extract a named metric from a telemetry series."""
    return [float(r.get(key, 0.0)) for r in series]


async def _score_from_reading(reading: dict) -> int:
    """Get resilience score for a single reading."""
    result = await score_device("_temporal", reading)
    return result["score"]


class TemporalCorrelator:
    """
    Analyses sequences of device telemetry to predict future resilience.

    Usage:
        tc = TemporalCorrelator()
        result = tc.analyse(series)  # series: list of telemetry dicts
    """

    def analyse(self, series: list[dict]) -> dict:
        """
        Analyse a time-ordered telemetry series and predict 72h resilience.

        Args:
            series: list of dicts, each with timestamp + metric fields.
                    Must be in chronological order (oldest first).

        Returns:
            dict: trend, predicted_score_72h, risk_factors, slopes, current_score

        Raises:
            ValueError: if series has fewer than 2 readings
        """
        if not series:
            raise ValueError("Series cannot be empty")
        if len(series) < _MIN_SERIES_LENGTH:
            raise ValueError(
                f"Need at least {_MIN_SERIES_LENGTH} readings for trend analysis. "
                f"Got {len(series)}."
            )

        # ── Extract metric arrays ──────────────────────────────────────
        cpu_vals    = _extract_metric(series, "cpu_percent")
        memory_vals = _extract_metric(series, "memory_percent")
        disk_vals   = _extract_metric(series, "disk_percent")

        # ── Compute slopes ─────────────────────────────────────────────
        window = series[-_TREND_WINDOW:] if len(series) >= _TREND_WINDOW else series
        cpu_slope    = _linear_slope(_extract_metric(window, "cpu_percent"))
        memory_slope = _linear_slope(_extract_metric(window, "memory_percent"))
        disk_slope   = _linear_slope(_extract_metric(window, "disk_percent"))

        # ── Current score from latest reading ──────────────────────────
        latest = series[-1]
        latest_telemetry = {
            k: v for k, v in latest.items()
            if k in ("cpu_percent", "memory_percent", "disk_percent")
        }

        # Synchronous score computation for temporal analysis
        from resilience.scorer import _metric_to_score
        cpu_s  = _metric_to_score(latest_telemetry.get("cpu_percent", 0), 50, 80)
        mem_s  = _metric_to_score(latest_telemetry.get("memory_percent", 0), 60, 85)
        disk_s = _metric_to_score(latest_telemetry.get("disk_percent", 0), 65, 85)
        weights = {"cpu": 0.25, "memory": 0.25, "disk": 0.5}
        current_score = int(
            (cpu_s * weights["cpu"] + mem_s * weights["memory"] + disk_s * weights["disk"])
        )
        if disk_s <= 20:
            current_score = min(current_score, 59)

        # ── Determine overall trend ────────────────────────────────────
        avg_slope = (cpu_slope + memory_slope + disk_slope) / 3

        if avg_slope > _RISE_THRESHOLD:
            trend = "degrading"
        elif avg_slope > 0.5:
            trend = "rising"
        elif avg_slope < -0.5:
            trend = "improving"
        else:
            trend = "stable"

        # ── Project 72h score ──────────────────────────────────────────
        # Estimate metric values 72 readings ahead (1 reading ≈ 1 hour)
        projected_cpu    = min(100, latest_telemetry.get("cpu_percent", 0)    + cpu_slope    * 72)
        projected_memory = min(100, latest_telemetry.get("memory_percent", 0) + memory_slope * 72)
        projected_disk   = min(100, latest_telemetry.get("disk_percent", 0)   + disk_slope   * 72)

        proj_cpu_s  = _metric_to_score(projected_cpu,    50, 80)
        proj_mem_s  = _metric_to_score(projected_memory, 60, 85)
        proj_disk_s = _metric_to_score(projected_disk,   65, 85)
        predicted_score = int(
            proj_cpu_s * weights["cpu"] +
            proj_mem_s * weights["memory"] +
            proj_disk_s * weights["disk"]
        )
        if proj_disk_s <= 20:
            predicted_score = min(predicted_score, 59)
        predicted_score = max(0, min(100, predicted_score))

        # ── Risk factor detection ──────────────────────────────────────
        risk_factors = []

        if cpu_slope > _RISE_THRESHOLD:
            risk_factors.append(
                f"CPU usage trending up {cpu_slope:.1f}%/hr — possible runaway process"
            )
        if memory_slope > _RISE_THRESHOLD:
            risk_factors.append(
                f"Memory usage trending up {memory_slope:.1f}%/hr — possible memory leak"
            )
        if disk_slope > _DISK_RISK_THRESHOLD:
            risk_factors.append(
                f"Disk usage growing {disk_slope:.1f}%/hr — will fill in "
                f"{int((100 - latest_telemetry.get('disk_percent', 50)) / disk_slope)}hr"
            )
        if max(cpu_vals) - min(cpu_vals) > 40:
            risk_factors.append("High CPU variance — possible intermittent spike")
        if latest_telemetry.get("disk_percent", 0) > 85:
            risk_factors.append("Disk above 85% — approaching critical threshold")
        if latest_telemetry.get("memory_percent", 0) > 85:
            risk_factors.append("Memory above 85% — approaching critical threshold")

        return {
            "trend": trend,
            "predicted_score_72h": predicted_score,
            "current_score": current_score,
            "risk_factors": risk_factors,
            "slopes": {
                "cpu": round(cpu_slope, 3),
                "memory": round(memory_slope, 3),
                "disk": round(disk_slope, 3),
            },
            "readings_analysed": len(series),
        }
