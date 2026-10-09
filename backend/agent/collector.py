"""
Device agent telemetry collector.
Lightweight module — only psutil + stdlib.
Runs on each monitored device, ships metrics to ResilientAI API.
"""
import platform
from datetime import datetime, timezone

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


def collect_metrics(device_id: str) -> dict:
    """
    Collect current device metrics.

    Returns a telemetry dict ready to POST to /devices/telemetry.
    Falls back to safe defaults if psutil is unavailable (test environments).
    """
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    if _PSUTIL_AVAILABLE:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        boot_time = psutil.boot_time()
        process_count = len(psutil.pids())
    else:
        # Safe test-environment fallback
        cpu = 0.0
        mem = 0.0
        disk = 0.0
        boot_time = 0.0
        process_count = 0

    return {
        "device_id": device_id,
        "timestamp": timestamp,
        "cpu_percent": round(cpu, 2),
        "memory_percent": round(mem, 2),
        "disk_percent": round(disk, 2),
        "boot_time": boot_time,
        "process_count": process_count,
        "platform": platform.system(),
        "hostname": platform.node(),
    }
