"""Liveness, database readiness, bounded bridge diagnostics, and SLO telemetry."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_db
from observability.metrics import metrics

router = APIRouter()


async def _check_all_bridges() -> dict:
    """Check configured bridges concurrently with strict per-dependency timeouts."""
    from bridges.threatfade import health_check as tf_health
    from bridges.fusionops import health_check as fo_health
    from bridges.reconos import health_check as ro_health
    from bridges.bugflow import health_check as bf_health
    from bridges.fdse import health_check as fdse_health
    from bridges.hezcast import health_check as hc_health
    from bridges.twinguard import health_check as tg_health
    from bridges.fadeforge import health_check as ff_health
    from bridges.ai_shield import health_check as ai_health
    from bridges.kalevio import health_check as kv_health
    from bridges.olvrix import health_check as ov_health
    from bridges.fadereach import health_check as fr_health

    checks = {
        "threatfade": (tf_health, settings.THREATFADE_URL),
        "fusionops": (fo_health, settings.FUSIONOPS_URL),
        "reconos": (ro_health, settings.RECONOS_URL),
        "bugflow": (bf_health, settings.BUGFLOW_URL),
        "fdse": (fdse_health, settings.FDSE_URL),
        "hezcast": (hc_health, settings.HEZCAST_URL),
        "twinguard": (tg_health, settings.TWINGUARD_URL),
        "fadeforge": (ff_health, settings.FADEFORGE_URL),
        "ai_shield": (ai_health, settings.AI_SHIELD_URL),
        "kalevio": (kv_health, settings.KALEVIO_URL),
        "olvrix": (ov_health, settings.OLVRIX_URL),
        "fadereach": (fr_health, settings.FADEREACH_URL),
    }

    async def check(name: str, fn, url: str) -> tuple[str, str]:
        if not url:
            return name, "not_configured"
        try:
            healthy = await asyncio.wait_for(fn(), timeout=settings.BRIDGE_HEALTH_TIMEOUT_SECONDS)
            return name, "ok" if healthy else "unreachable"
        except asyncio.TimeoutError:
            return name, "timeout"
        except Exception:
            # Avoid leaking URLs, provider errors, or credentials in health responses.
            return name, "error"

    pairs = await asyncio.gather(*(check(name, fn, url) for name, (fn, url) in checks.items()))
    return dict(pairs)


@router.get("/")
async def health(response: Response):
    """Detailed dependency status; unlike liveness, this endpoint may be degraded."""
    bridges = await _check_all_bridges()
    wired = sum(1 for value in bridges.values() if value == "ok")
    pending = sum(1 for value in bridges.values() if value == "not_configured")
    unhealthy = sum(1 for value in bridges.values() if value in {"unreachable", "timeout", "error"})
    if unhealthy:
        response.status_code = 503
    return {
        "status": "degraded" if unhealthy else "ok",
        "version": settings.VERSION,
        "app": settings.APP_NAME,
        "bridges": bridges,
        "bridge_summary": {
            "wired": wired,
            "unreachable": sum(1 for value in bridges.values() if value in {"unreachable", "timeout", "error"}),
            "not_configured": pending,
            "total": len(bridges),
        },
    }


@router.get("/live")
async def liveness():
    """Liveness must be cheap and independent of external services."""
    return {"alive": True}


@router.get("/ready")
async def readiness(response: Response, db: AsyncSession = Depends(get_db)):
    """Production readiness requires an enabled data plane, database access, and exact schema."""
    if not settings.DATA_PLANE_ENABLED:
        response.status_code = 503 if settings.ENVIRONMENT.lower() == "production" else 200
        return {
            "ready": settings.ENVIRONMENT.lower() != "production",
            "mode": "health_only",
            "business_data_plane_ready": False,
            "reason": "business_data_plane_disabled",
        }
    try:
        await db.execute(text("SELECT 1"))
        revisions = list((await db.execute(text("SELECT version_num FROM alembic_version"))).scalars().all())
    except Exception:
        response.status_code = 503
        return {"ready": False, "reason": "database_unavailable_or_unmigrated"}
    if revisions != [settings.DB_SCHEMA_REVISION]:
        response.status_code = 503
        return {
            "ready": False,
            "reason": "schema_revision_mismatch",
            "expected_revision": settings.DB_SCHEMA_REVISION,
            "found_revision_count": len(revisions),
        }
    return {"ready": True, "mode": "business_data_plane", "schema_revision": revisions[0]}


@router.get("/metrics")
async def prometheus_metrics():
    """Prometheus exposition; protected by the normal API authentication perimeter."""
    if not settings.METRICS_ENABLED:
        return Response(status_code=404)
    return Response(
        content=metrics.render_prometheus(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/slo")
async def slo_snapshot():
    """Return a process-local SLO snapshot, never misrepresented as a durable time window."""
    if not settings.METRICS_ENABLED:
        return Response(status_code=404)
    snapshot = metrics.snapshot()
    enough_data = snapshot["request_count"] >= 20
    availability = 1.0 - snapshot["server_error_rate"]
    latency = snapshot["approx_p95_seconds_upper_bound"]
    within_target = enough_data and (
        availability >= settings.SLO_TARGET_AVAILABILITY
        and latency is not None and latency <= settings.SLO_TARGET_P95_SECONDS
    )
    return {
        **snapshot,
        "targets": {
            "availability": settings.SLO_TARGET_AVAILABILITY,
            "p95_latency_seconds": settings.SLO_TARGET_P95_SECONDS,
        },
        "availability_estimate": availability,
        "status": "insufficient_data" if not enough_data else ("within_target" if within_target else "target_breached"),
        "disclaimer": "Process-local counters reset on restart and are not a durable SLO/SLA measurement.",
    }


@router.get("/bridges")
async def bridge_status():
    """Dedicated endpoint for ecosystem bridge diagnostics."""
    bridges = await _check_all_bridges()
    return {
        "bridges": bridges,
        "ecosystem": {
            "wired_today": ["threatfade", "fusionops"],
            "env_only": ["reconos", "bugflow", "ai_shield"],
            "sprint_7": ["fdse", "hezcast", "twinguard", "fadeforge"],
            "sprint_8": ["kalevio", "olvrix", "fadereach"],
        },
    }
