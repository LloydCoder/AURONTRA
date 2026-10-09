"""
Olvrix Platform Bridge — client device events → ResilientAI ticket queue.
Olvrix: v0.3.1, 93 files, 15,064 lines, 5 payment gateways including
NOWPayments USDT/USDC, deployment-ready.

What flows IN from Olvrix:
  - Client device events → auto-tickets in ResilientAI
  - Agency client ticket signals → ResilientAI resolution queue
  - Olvrix widget errors → ResilientAI incident tickets

What flows OUT to Olvrix:
  - Resolved tickets → Olvrix client health dashboard
  - Threat events → Olvrix security feed
  - Resilience scores → Olvrix platform device health view
"""
import httpx
import logging
from core.config import settings

logger = logging.getLogger(__name__)


async def receive_client_event(event: dict) -> dict:
    """
    Process a client event from Olvrix's flywheel orchestrator.
    Maps it to a ResilientAI ticket or threat event.
    """
    event_type = event.get("event_type", "")
    if "error" in event_type or "crash" in event_type:
        return {
            "action": "create_ticket",
            "title": event.get("title", "Olvrix client error"),
            "description": event.get("detail", ""),
            "source": "olvrix",
            "priority": "medium",
        }
    elif "threat" in event_type or "security" in event_type:
        return {
            "action": "create_threat_event",
            "title": event.get("title", "Olvrix security event"),
            "source": "olvrix",
        }
    return {"action": "log", "event": event}


async def push_ticket_resolution(
    org_id: str,
    ticket_id: str,
    resolution: str,
    ai_resolved: bool,
) -> bool:
    """
    Push ticket resolution back to Olvrix client health dashboard.
    Olvrix shows the resolution status in the agency client view.
    """
    if not settings.OLVRIX_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.OLVRIX_URL}/bridge/resilientai/ticket-resolved",
                json={
                    "org_id": org_id,
                    "ticket_id": ticket_id,
                    "resolution": resolution,
                    "ai_resolved": ai_resolved,
                    "source": "resilientai",
                },
                headers={"X-Bridge-Key": settings.OLVRIX_BRIDGE_KEY},
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/olvrix] push_ticket_resolution failed: {e}")
        return False


async def push_resilience_scores(org_id: str, scores: list[dict]) -> bool:
    """Push device resilience scores to Olvrix's platform health view."""
    if not settings.OLVRIX_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.OLVRIX_URL}/bridge/resilientai/scores",
                json={"org_id": org_id, "scores": scores},
                headers={"X-Bridge-Key": settings.OLVRIX_BRIDGE_KEY},
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/olvrix] push_resilience_scores failed: {e}")
        return False


async def health_check() -> bool:
    if not settings.OLVRIX_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.OLVRIX_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
