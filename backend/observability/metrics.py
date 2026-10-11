"""Bounded-cardinality process-local Prometheus metrics and SLO snapshots."""
from __future__ import annotations

import threading
from collections import defaultdict
from math import inf

_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
_ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "OTHER"})


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class ProcessMetrics:
    """Thread-safe in-process counters; resets on restart and is not a durable SLI store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests = defaultdict(int)
        self._histograms = defaultdict(lambda: {"count": 0, "sum": 0.0, "buckets": [0] * len(_BUCKETS)})

    def record(self, method: str, route: str, status_code: int, duration_seconds: float) -> None:
        safe_method = method.upper() if method.upper() in _ALLOWED_METHODS else "OTHER"
        safe_route = route if isinstance(route, str) and route.startswith("/") and len(route) <= 160 else "unmatched"
        # FastAPI route templates are used; raw path parameters are never labels.
        status_class = f"{int(status_code) // 100}xx" if 100 <= int(status_code) <= 599 else "unknown"
        key = (safe_method, safe_route, status_class)
        with self._lock:
            self._requests[key] += 1
            histogram = self._histograms[(safe_method, safe_route)]
            histogram["count"] += 1
            histogram["sum"] += max(0.0, float(duration_seconds))
            for i, bound in enumerate(_BUCKETS):
                if duration_seconds <= bound:
                    histogram["buckets"][i] += 1

    def snapshot(self) -> dict:
        with self._lock:
            requests = dict(self._requests)
            histograms = {
                key: {"count": value["count"], "sum": value["sum"], "buckets": list(value["buckets"])}
                for key, value in self._histograms.items()
            }
        total = sum(requests.values())
        errors = sum(count for (_, _, status), count in requests.items() if status in {"5xx", "unknown"})
        latency_samples = sum(item["count"] for item in histograms.values())
        bucket_totals = [sum(item["buckets"][i] for item in histograms.values()) for i in range(len(_BUCKETS))]
        p95_bound = next((bound for bound, count in zip(_BUCKETS, bucket_totals) if count >= latency_samples * 0.95), inf)
        return {
            "window": "process_lifetime",
            "durable": False,
            "request_count": total,
            "server_error_count": errors,
            "server_error_rate": (errors / total) if total else 0.0,
            "latency_sample_count": latency_samples,
            "approx_p95_seconds_upper_bound": p95_bound if p95_bound != inf else None,
            "latency_buckets": {str(bound): count for bound, count in zip(_BUCKETS, bucket_totals)},
        }

    def render_prometheus(self) -> str:
        with self._lock:
            requests = sorted(self._requests.items())
            histograms = {
                key: {"count": value["count"], "sum": value["sum"], "buckets": list(value["buckets"])}
                for key, value in self._histograms.items()
            }
        lines = [
            "# HELP aurontra_http_requests_total HTTP responses observed in this process.",
            "# TYPE aurontra_http_requests_total counter",
        ]
        for (method, route, status_class), count in requests:
            lines.append(
                f'aurontra_http_requests_total{{method="{_label(method)}",route="{_label(route)}",status_class="{status_class}"}} {count}'
            )
        lines.extend([
            "# HELP aurontra_http_request_duration_seconds Request duration histogram in seconds.",
            "# TYPE aurontra_http_request_duration_seconds histogram",
        ])
        for (method, route), item in sorted(histograms.items()):
            for bound, count in zip(_BUCKETS, item["buckets"]):
                lines.append(
                    f'aurontra_http_request_duration_seconds_bucket{{method="{_label(method)}",route="{_label(route)}",le="{bound:g}"}} {count}'
                )
            lines.append(
                f'aurontra_http_request_duration_seconds_bucket{{method="{_label(method)}",route="{_label(route)}",le="+Inf"}} {item["count"]}'
            )
            lines.append(f'aurontra_http_request_duration_seconds_count{{method="{_label(method)}",route="{_label(route)}"}} {item["count"]}')
            lines.append(f'aurontra_http_request_duration_seconds_sum{{method="{_label(method)}",route="{_label(route)}"}} {item["sum"]:.9f}')
        lines.append("# HELP aurontra_metrics_process_local 1 means metrics reset when this process restarts.")
        lines.append("# TYPE aurontra_metrics_process_local gauge")
        lines.append("aurontra_metrics_process_local 1")
        return "\n".join(lines) + "\n"


metrics = ProcessMetrics()
