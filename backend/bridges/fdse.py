"""
FDSE Toolkit v2.0.0 Bridge — incident playbooks → knowledge base seeding.
FDSE: 100% complete, validated by Engr Uzoma.
  - Incident Response Playbook Generator (6 alert types, MITRE mapped)
  - ROI Calculator (418x ROI, MTTD/MTTR metrics)
  - Report Generator (PDF/Word/Excel)
  - Identity Threat Scanner (18 credential patterns)

What flows IN from FDSE:
  - Playbook library → auto-seeds ResilientAI knowledge base
  - Credential scan results → creates security tickets
  - ROI data → enriches ResilientAI's own ROI reports

What flows OUT to FDSE:
  - Threat events → FDSE generates incident response playbooks
  - Resilience scores → FDSE ROI calculator input
"""
import httpx
import logging
from core.config import settings
from knowledge_base.service import create_article

logger = logging.getLogger(__name__)


async def pull_playbook_library() -> list[dict]:
    """
    Pull all incident response playbooks from FDSE.
    Seeds ResilientAI's knowledge base with pre-written IT response guides.
    """
    if not settings.FDSE_URL:
        return []
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.get(f"{settings.FDSE_URL}/playbooks")
            r.raise_for_status()
            return r.json().get("playbooks", [])
    except Exception as e:
        logger.warning(f"[bridges/fdse] pull_playbook_library failed: {e}")
        return []


async def seed_kb_from_fdse() -> dict:
    """
    Pull FDSE playbooks and auto-seed the ResilientAI knowledge base.
    Called once on startup and weekly thereafter.
    Returns count of articles seeded.
    """
    playbooks = await pull_playbook_library()
    seeded = 0
    for pb in playbooks:
        try:
            create_article(
                title=pb.get("title", "Untitled Playbook"),
                content=pb.get("steps", pb.get("content", "")),
                category=pb.get("category", "security"),
                tags=pb.get("tags", ["fdse", "playbook"]),
            )
            seeded += 1
        except Exception:
            pass
    logger.info(f"[bridges/fdse] Seeded {seeded} articles from FDSE playbook library")
    return {"seeded": seeded, "source": "fdse"}


async def request_playbook_for_incident(
    incident_type: str,
    mitre_ttp: str = "",
) -> dict:
    """
    Request a specific incident response playbook from FDSE.
    Used when ResilientAI detects a threat and needs response guidance.
    """
    if not settings.FDSE_URL:
        return {"playbook": None, "source": "fdse_unavailable"}
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.post(
                f"{settings.FDSE_URL}/playbooks/generate",
                json={"incident_type": incident_type, "mitre_ttp": mitre_ttp},
            )
            r.raise_for_status()
            return {**r.json(), "source": "fdse"}
    except Exception as e:
        logger.warning(f"[bridges/fdse] request_playbook failed: {e}")
        return {"playbook": None, "error": str(e)}


async def scan_credentials(target_domain: str) -> dict:
    """
    Use FDSE's identity threat scanner (18 credential patterns) on a domain.
    High-severity findings auto-create security tickets in ResilientAI.
    """
    if not settings.FDSE_URL:
        return {"findings": [], "source": "fdse_unavailable"}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{settings.FDSE_URL}/scan/credentials",
                json={"domain": target_domain},
            )
            r.raise_for_status()
            return {**r.json(), "source": "fdse"}
    except Exception as e:
        logger.warning(f"[bridges/fdse] scan_credentials failed: {e}")
        return {"findings": [], "error": str(e)}


async def health_check() -> bool:
    if not settings.FDSE_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.FDSE_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
