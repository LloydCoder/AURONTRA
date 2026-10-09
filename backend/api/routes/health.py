"""
Health router — liveness, readiness, and full ecosystem bridge status.
Shows all 10 bridge connections at a glance.
"""
from fastapi import APIRouter, Response
from core.config import settings

router = APIRouter()


async def _check_all_bridges() -> dict:
    """Check health of all wired ecosystem bridges."""
    from bridges.threatfade import health_check as tf_health
    from bridges.fusionops  import health_check as fo_health
    from bridges.reconos    import health_check as ro_health
    from bridges.bugflow    import health_check as bf_health
    from bridges.fdse       import health_check as fdse_health
    from bridges.hezcast    import health_check as hc_health
    from bridges.twinguard  import health_check as tg_health
    from bridges.fadeforge  import health_check as ff_health
    from bridges.ai_shield  import health_check as ai_health
    from bridges.kalevio    import health_check as kv_health
    from bridges.olvrix     import health_check as ov_health
    from bridges.fadereach  import health_check as fr_health

    checks = {
        "threatfade":  (tf_health,  settings.THREATFADE_URL),
        "fusionops":   (fo_health,  settings.FUSIONOPS_URL),
        "reconos":     (ro_health,  settings.RECONOS_URL),
        "bugflow":     (bf_health,  settings.BUGFLOW_URL),
        "fdse":        (fdse_health,settings.FDSE_URL),
        "hezcast":     (hc_health,  settings.HEZCAST_URL),
        "twinguard":   (tg_health,  settings.TWINGUARD_URL),
        "fadeforge":   (ff_health,  settings.FADEFORGE_URL),
        "ai_shield":   (ai_health,  settings.AI_SHIELD_URL),
        "kalevio":     (kv_health,  settings.KALEVIO_URL),
        "olvrix":      (ov_health,  settings.OLVRIX_URL),
        "fadereach":   (fr_health,  settings.FADEREACH_URL),
    }

    results = {}
    for name, (fn, url) in checks.items():
        if not url:
            results[name] = "not_configured"
        else:
            ok = await fn()
            results[name] = "ok" if ok else "unreachable"

    return results


@router.get("/")
async def health():
    """Primary health check — always 200 if API is up. Shows all bridges."""
    bridges = await _check_all_bridges()
    wired   = sum(1 for v in bridges.values() if v == "ok")
    pending = sum(1 for v in bridges.values() if v == "not_configured")
    return {
        "status":  "ok",
        "version": settings.VERSION,
        "app":     settings.APP_NAME,
        "bridges": bridges,
        "bridge_summary": {
            "wired":          wired,
            "unreachable":    sum(1 for v in bridges.values() if v == "unreachable"),
            "not_configured": pending,
            "total":          len(bridges),
        },
    }


@router.get("/live")
async def liveness():
    return {"alive": True}


@router.get("/ready")
async def readiness():
    """Readiness — only requires ThreatFade (the core oracle)."""
    from bridges.threatfade import health_check as tf_health
    tf_ok = await tf_health()
    if not tf_ok:
        return Response(
            content='{"ready":false,"reason":"ThreatFade bridge unreachable"}',
            status_code=503,
            media_type="application/json",
        )
    return {"ready": True}


@router.get("/bridges")
async def bridge_status():
    """Dedicated endpoint for ecosystem bridge status dashboard."""
    bridges = await _check_all_bridges()
    return {
        "bridges": bridges,
        "ecosystem": {
            "wired_today":    ["threatfade", "fusionops"],
            "env_only":       ["reconos", "bugflow", "ai_shield"],
            "sprint_7":       ["fdse", "hezcast", "twinguard", "fadeforge"],
            "sprint_8":       ["kalevio", "olvrix", "fadereach"],
        },
    }
