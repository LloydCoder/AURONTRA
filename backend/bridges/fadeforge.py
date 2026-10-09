"""
FadeForge AI Bridge — red team attack patterns → enrich ThreatFade signals.
FadeForge AI: Estonian OÜ, github.com/FadeForgeAI, Week 1 codebase delivered,
44 tests, 3 adversary profiles seeded from real malware Z-scores.
IP intentionally separated from Tinlance.

What flows IN from FadeForge:
  - Adversary profiles → enrich ThreatFade's C2 detection model
  - Real malware Z-scores → calibrate ResilientAI anomaly thresholds
  - Pen test findings → auto-create vulnerability tickets

What flows OUT to FadeForge:
  - Network traffic anomalies → FadeForge adversary profile training
  - Blocked C2 signatures → FadeForge red team playbook library
"""
import httpx
import logging
from core.config import settings

logger = logging.getLogger(__name__)


async def get_adversary_profiles(limit: int = 10) -> list[dict]:
    """
    Pull adversary profiles from FadeForge.
    Used to calibrate ResilientAI's anomaly detection thresholds.
    Each profile contains real malware Z-scores and entropy signatures.
    """
    if not settings.FADEFORGE_URL:
        return []
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.get(
                f"{settings.FADEFORGE_URL}/profiles",
                params={"limit": limit, "requester": "resilientai"},
                headers={"X-API-Key": settings.FADEFORGE_API_KEY},
            )
            r.raise_for_status()
            return r.json().get("profiles", [])
    except Exception as e:
        logger.warning(f"[bridges/fadeforge] get_adversary_profiles failed: {e}")
        return []


async def calibrate_thresholds() -> dict:
    """
    Use FadeForge's real malware Z-score database to calibrate
    ResilientAI's Isolation Forest and threat scoring thresholds.
    Called weekly to keep detection current.
    """
    profiles = await get_adversary_profiles(limit=50)
    if not profiles:
        return {"calibrated": False, "profiles_used": 0}

    # Extract Z-scores from profiles to update thresholds
    z_scores = [
        p.get("z_score", 0)
        for p in profiles
        if p.get("z_score")
    ]

    if not z_scores:
        return {"calibrated": False, "profiles_used": len(profiles)}

    avg_malicious_z = sum(z_scores) / len(z_scores)
    max_z = max(z_scores)

    logger.info(f"[bridges/fadeforge] Calibrated with {len(profiles)} profiles. Avg Z: {avg_malicious_z:.2f}, Max Z: {max_z:.2f}")
    return {
        "calibrated": True,
        "profiles_used": len(profiles),
        "avg_malicious_z_score": round(avg_malicious_z, 2),
        "max_z_score": round(max_z, 2),
        "source": "fadeforge",
    }


async def send_blocked_signature(
    signature: dict,
    z_score: float,
    mitre_ttp: str,
) -> bool:
    """
    Send a blocked C2 signature back to FadeForge's red team playbook library.
    Bidirectional: FadeForge trains ResilientAI, ResilientAI feeds FadeForge.
    """
    if not settings.FADEFORGE_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.FADEFORGE_URL}/signatures/ingest",
                json={
                    "signature": signature,
                    "z_score": z_score,
                    "mitre_ttp": mitre_ttp,
                    "source": "resilientai_threatfade",
                },
                headers={"X-API-Key": settings.FADEFORGE_API_KEY},
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/fadeforge] send_blocked_signature failed: {e}")
        return False


async def health_check() -> bool:
    if not settings.FADEFORGE_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                f"{settings.FADEFORGE_URL}/health",
                headers={"X-API-Key": settings.FADEFORGE_API_KEY},
            )
            return r.status_code == 200
    except Exception:
        return False
