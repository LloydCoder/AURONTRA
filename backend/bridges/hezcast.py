"""
HezCast Engine Bridge — resolved tickets → auto-generated customer comms.
HezCast: 287 tests, mobile-responsive, NOWPayments crypto, Canvas built.
Named after Daddy Hezekiah.

What flows OUT to HezCast:
  - Resolved ticket summaries → HezCast generates customer update emails
  - Incident reports → HezCast generates status page content
  - Threat blocked notifications → HezCast drafts security bulletins

What flows IN from HezCast:
  - Generated email content → ready to send via Resend
  - Campaign distribution → spreads ResilientAI's reports to stakeholders
"""
import httpx
import logging
from core.config import settings

logger = logging.getLogger(__name__)


async def generate_incident_update(
    incident_title: str,
    resolution_summary: str,
    severity: str = "medium",
    recipient_count: int = 1,
) -> dict:
    """
    Send a resolved incident to HezCast for auto-generated customer comms.
    HezCast returns a ready-to-send email template.
    """
    if not settings.HEZCAST_URL:
        return {
            "generated": False,
            "source": "hezcast_unavailable",
            "fallback_subject": f"[ResilientAI] Incident Resolved: {incident_title}",
            "fallback_body": resolution_summary,
        }
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.post(
                f"{settings.HEZCAST_URL}/generate/incident-update",
                json={
                    "title": incident_title,
                    "resolution": resolution_summary,
                    "severity": severity,
                    "context": "IT resilience platform — ResilientAI",
                },
            )
            r.raise_for_status()
            return {**r.json(), "source": "hezcast", "generated": True}
    except Exception as e:
        logger.warning(f"[bridges/hezcast] generate_incident_update failed: {e}")
        return {
            "generated": False,
            "error": str(e),
            "fallback_subject": f"[ResilientAI] Resolved: {incident_title}",
            "fallback_body": resolution_summary,
        }


async def generate_security_bulletin(
    threat_type: str,
    mitre_ttp: str,
    blocked: bool,
    org_id: str,
) -> dict:
    """
    Generate a security bulletin for a blocked threat.
    Distributed to org stakeholders via HezCast's campaign engine.
    """
    if not settings.HEZCAST_URL:
        return {"generated": False, "source": "hezcast_unavailable"}
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.post(
                f"{settings.HEZCAST_URL}/generate/security-bulletin",
                json={
                    "threat_type": threat_type,
                    "mitre_ttp": mitre_ttp,
                    "blocked": blocked,
                    "org_id": org_id,
                    "platform": "ResilientAI",
                },
            )
            r.raise_for_status()
            return {**r.json(), "source": "hezcast", "generated": True}
    except Exception as e:
        logger.warning(f"[bridges/hezcast] generate_security_bulletin failed: {e}")
        return {"generated": False, "error": str(e)}


async def distribute_roi_report(
    org_id: str,
    roi_data: dict,
    recipient_emails: list[str],
) -> dict:
    """
    Send ResilientAI ROI report to HezCast for branded distribution.
    HezCast packages it into a professional PDF email campaign.
    """
    if not settings.HEZCAST_URL:
        return {"distributed": False, "source": "hezcast_unavailable"}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                f"{settings.HEZCAST_URL}/distribute/report",
                json={
                    "org_id": org_id,
                    "report_type": "roi",
                    "data": roi_data,
                    "recipients": recipient_emails,
                    "platform": "ResilientAI",
                },
            )
            r.raise_for_status()
            return {**r.json(), "source": "hezcast", "distributed": True}
    except Exception as e:
        logger.warning(f"[bridges/hezcast] distribute_roi_report failed: {e}")
        return {"distributed": False, "error": str(e)}


async def health_check() -> bool:
    if not settings.HEZCAST_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.HEZCAST_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
