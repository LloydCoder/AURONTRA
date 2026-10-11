"""
Device agent telemetry collector.
Lightweight module — only psutil + stdlib.
Runs on each enrolled device and emits the versioned telemetry schema.
"""
import platform
from datetime import datetime, timezone
from uuid import uuid4

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


def collect_metrics(device_id: str) -> dict:
    """
    Collect current device metrics.

    Returns a telemetry dict ready to POST to /agent/v1/telemetry.
    Device identity is established by the DPoP token, not a caller-supplied device_id.
    Missing psutil is a hard failure: zero-filled fallback metrics could falsely report health.
    """
    if not _PSUTIL_AVAILABLE:
        raise RuntimeError("psutil is required for trustworthy endpoint telemetry")
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    if _PSUTIL_AVAILABLE:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        boot_time = psutil.boot_time()
        process_count = len(psutil.pids())

    current_platform = platform.system()
    if current_platform not in {"Linux", "Windows", "Darwin", "FreeBSD", "OpenBSD", "NetBSD"}:
        current_platform = "Unknown"

    return {
        "event_id": str(uuid4()),
        "schema_version": "1",
        "timestamp": timestamp,
        "cpu_percent": round(cpu, 2),
        "memory_percent": round(mem, 2),
        "disk_percent": round(disk, 2),
        "boot_time": boot_time,
        "process_count": process_count,
        "platform": current_platform,
    }
