"""Security assurance and lightweight concurrency regression tests."""
from concurrent.futures import ThreadPoolExecutor

from core.auth import AuthorizationDenied, authorize_claims
from observability.metrics import ProcessMetrics


def test_metrics_registry_remains_consistent_under_concurrent_load():
    registry = ProcessMetrics()
    total = 10_000

    def record_batch(start: int, end: int):
        for index in range(start, end):
            status = 500 if index % 101 == 0 else 200
            route = "/devices/{device_id}" if index % 2 else "/tickets"
            registry.record("GET", route, status, (index % 20) / 1000)

    workers = 8
    batch = total // workers
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(record_batch, i * batch, (i + 1) * batch)
            for i in range(workers)
        ]
        for future in futures:
            future.result()

    snapshot = registry.snapshot()
    assert snapshot["request_count"] == total
    assert snapshot["server_error_count"] == sum(1 for i in range(total) if i % 101 == 0)
    assert snapshot["latency_sample_count"] == total
    assert len(registry._histograms) == 2


def test_unknown_or_missing_roles_fail_closed_in_jwt_policy():
    claims = {
        "sub": "operator-1",
        "org_id": "tenant-1",
        "role": "superadmin",
    }
    try:
        authorize_claims(claims, "GET", "/admin/audit")
    except AuthorizationDenied:
        pass
    else:
        raise AssertionError("Unknown roles must not be accepted")

    claims["role"] = "org:viewer"
    try:
        authorize_claims(claims, "POST", "/admin/api-keys")
    except AuthorizationDenied:
        pass
    else:
        raise AssertionError("Viewer must not administer credentials")
