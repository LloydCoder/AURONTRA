"""
Resilience scoring engine.
Converts raw device telemetry into a 0-100 composite score.
"""
from core.config import settings


def score_to_status(score: int) -> str:
    """Map numeric score to human-readable status."""
    if score >= settings.RESILIENCE_WARN_THRESHOLD:
        return "healthy"
    elif score >= settings.RESILIENCE_CRITICAL_THRESHOLD:
        return "warning"
    else:
        return "critical"


def _metric_to_score(value: float, good_threshold: float = 60.0, bad_threshold: float = 80.0) -> int:
    """
    Convert a usage percentage to a component score.
    Low usage = high score. High usage = low score.
    """
    if value <= good_threshold:
        return 100
    elif value >= bad_threshold:
        return max(0, int(100 - (value - bad_threshold) * 8))
    else:
        # Linear interpolation between thresholds
        ratio = (value - good_threshold) / (bad_threshold - good_threshold)
        return int(100 - ratio * 55)


async def score_device(device_id: str, telemetry: dict) -> dict:
    """
    Compute a composite resilience score for a device.

    Args:
        device_id: unique device identifier
        telemetry: dict with keys: cpu_percent, memory_percent, disk_percent

    Returns:
        dict with score (0-100), status, components breakdown
    """
    if not telemetry:
        return {
            "device_id": device_id,
            "score": 0,
            "status": "unknown",
            "components": {},
        }

    components = {}

    if "cpu_percent" in telemetry:
        components["cpu"] = _metric_to_score(
            telemetry["cpu_percent"], good_threshold=50, bad_threshold=80
        )

    if "memory_percent" in telemetry:
        components["memory"] = _metric_to_score(
            telemetry["memory_percent"], good_threshold=60, bad_threshold=85
        )

    if "disk_percent" in telemetry:
        components["disk"] = _metric_to_score(
            telemetry["disk_percent"], good_threshold=65, bad_threshold=85
        )

    if not components:
        return {
            "device_id": device_id,
            "score": 0,
            "status": "unknown",
            "components": {},
        }

    # Weighted average — disk failures are most catastrophic
    weights = {"cpu": 0.25, "memory": 0.25, "disk": 0.5}
    total_weight = sum(weights[k] for k in components)
    weighted_sum = sum(components[k] * weights.get(k, 0.33) for k in components)
    score = int(weighted_sum / total_weight)
    score = max(0, min(100, score))

    # Hard floor: if any single critical component is very low, cap the score
    if components.get("disk", 100) <= 20:
        score = min(score, settings.RESILIENCE_WARN_THRESHOLD - 1)
    if components.get("cpu", 100) <= 10 or components.get("memory", 100) <= 10:
        score = min(score, settings.RESILIENCE_WARN_THRESHOLD - 1)

    return {
        "device_id": device_id,
        "score": score,
        "status": score_to_status(score),
        "components": components,
    }
