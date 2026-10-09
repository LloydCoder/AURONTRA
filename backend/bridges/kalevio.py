"""
KalevioAI Bridge — compliance gaps → remediation tickets + score sync.
KalevioAI: FastAPI + Next.js 15 + PostgreSQL 16 + pgvector + LangChain,
€49/€199/€499 pricing, Supabase SQL migration with RLS + pgvector complete.

What flows IN from KalevioAI:
  - NIS2/DORA compliance gaps → auto-tickets in ResilientAI
  - Compliance score → appears in ResilientAI dashboard
  - Evidence gaps → self-healing playbook triggers

What flows OUT to KalevioAI:
  - ResilientAI compliance report → updates KalevioAI compliance score
  - ThreatFade events → KalevioAI incident evidence log
  - Resilience scores → KalevioAI's device health evidence
"""
import httpx
import logging
from core.config import settings

logger = logging.getLogger(__name__)


async def get_compliance_gaps(org_id: str, framework: str = "NIS2") -> list[dict]:
    """
    Pull active compliance gaps from KalevioAI for an org.
    Each gap becomes a ResilientAI remediation ticket.
    """
    if not settings.KALEVIO_URL:
        return []
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.get(
                f"{settings.KALEVIO_URL}/compliance/gaps",
                params={"org_id": org_id, "framework": framework},
                headers={"Authorization": f"Bearer {settings.KALEVIO_API_KEY}"},
            )
            r.raise_for_status()
            return r.json().get("gaps", [])
    except Exception as e:
        logger.warning(f"[bridges/kalevio] get_compliance_gaps failed: {e}")
        return []


async def push_resilience_report(
    org_id: str,
    compliance_report: dict,
    resilience_scores: list[dict],
) -> bool:
    """
    Push ResilientAI's compliance report + device scores to KalevioAI.
    KalevioAI updates the org's compliance evidence bundle.
    """
    if not settings.KALEVIO_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.post(
                f"{settings.KALEVIO_URL}/evidence/ingest",
                json={
                    "org_id": org_id,
                    "source": "resilientai",
                    "compliance_report": compliance_report,
                    "device_scores": resilience_scores,
                },
                headers={"Authorization": f"Bearer {settings.KALEVIO_API_KEY}"},
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/kalevio] push_resilience_report failed: {e}")
        return False


async def push_threat_event(
    org_id: str,
    event: dict,
) -> bool:
    """
    Send a ThreatFade-detected event to KalevioAI as compliance evidence.
    Each blocked threat becomes incident evidence in the NIS2/DORA report.
    """
    if not settings.KALEVIO_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.KALEVIO_URL}/incidents/ingest",
                json={
                    "org_id": org_id,
                    "source": "resilientai_threatfade",
                    "event": event,
                },
                headers={"Authorization": f"Bearer {settings.KALEVIO_API_KEY}"},
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/kalevio] push_threat_event failed: {e}")
        return False


async def health_check() -> bool:
    if not settings.KALEVIO_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.KALEVIO_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
