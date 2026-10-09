"""
FadeReach Bridge — IT resilience proof → MSP/IT team outreach pipeline.
FadeReach: Growth hub, fadereach.tinlance.com → fadereach.ai,
$49/$99/$299/$999 pricing, FastAPI + EC2 + Listmonk + Claude + n8n.

What flows OUT to FadeReach:
  - IT resilience proof points → opportunity feed
  - Org trial signups → FadeReach nurture sequence (Day 0-90)
  - ROI report data → FadeReach outreach personalisation

What flows IN from FadeReach:
  - Trial signup events → onboard new ResilientAI orgs
  - IT/MSP prospect data → ResilientAI waitlist
  - Campaign performance → improves ResilientAI messaging
"""
import httpx
import logging
from core.config import settings

logger = logging.getLogger(__name__)


async def send_trial_signup(
    org_id: str,
    org_name: str,
    admin_email: str,
    plan: str,
    device_count: int,
) -> bool:
    """
    Notify FadeReach of a new ResilientAI trial signup.
    FadeReach starts a Day 0-90 nurture sequence immediately.
    """
    if not settings.FADEREACH_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.FADEREACH_URL}/leads/ingest",
                json={
                    "source_product": "resilientai",
                    "lead_type": "trial_signup",
                    "org_id": org_id,
                    "org_name": org_name,
                    "email": admin_email,
                    "plan": plan,
                    "device_count": device_count,
                    "segment": "it_msp",
                    "tags": ["resilientai", "trial", f"plan_{plan}"],
                },
                headers={"X-API-Key": settings.FADEREACH_API_KEY},
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/fadereach] send_trial_signup failed: {e}")
        return False


async def send_proof_point(
    metric_type: str,
    value: str,
    context: str,
) -> bool:
    """
    Send an IT resilience proof point to FadeReach's opportunity feed.
    Examples: "80% ticket resolution rate", "ThreatFade Z=14.76 blocked"
    FadeReach uses these as social proof in outreach campaigns.
    """
    if not settings.FADEREACH_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.FADEREACH_URL}/proof-points/ingest",
                json={
                    "source": "resilientai",
                    "metric_type": metric_type,
                    "value": value,
                    "context": context,
                },
                headers={"X-API-Key": settings.FADEREACH_API_KEY},
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/fadereach] send_proof_point failed: {e}")
        return False


async def send_roi_data(org_id: str, roi_report: dict) -> bool:
    """
    Send ROI report data to FadeReach for outreach personalisation.
    FadeReach uses the actual ROI multiple in personalised outreach emails.
    """
    if not settings.FADEREACH_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.FADEREACH_URL}/enrichment/roi",
                json={
                    "org_id": org_id,
                    "source": "resilientai",
                    "roi_multiple": roi_report.get("roi_multiple"),
                    "labour_saved": roi_report.get("labour_cost_saved"),
                    "threats_blocked": roi_report.get("threats_blocked"),
                },
                headers={"X-API-Key": settings.FADEREACH_API_KEY},
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/fadereach] send_roi_data failed: {e}")
        return False


async def health_check() -> bool:
    if not settings.FADEREACH_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.FADEREACH_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
