"""
BugFlow Elite v6 Bridge — surface-change detection → predictive resilience.
BugFlow: 51 modules, 128 tests, Telegram alerts, ThreatFade C2 integrated.

What flows IN from BugFlow:
  - change_detection.py results → surface changes = early warning signals
  - Vulnerability findings → creates auto-tickets in ResilientAI
  - C2 detection events → enriches ThreatFade signals

What flows OUT to BugFlow:
  - ResilientAI device list → BugFlow knows what to scan
  - Threat events → BugFlow feeds its detection model
"""
import httpx
import logging
from core.config import settings

logger = logging.getLogger(__name__)


async def get_surface_changes(target: str) -> dict:
    """
    Pull surface change detection results from BugFlow.
    Surface changes = early signal for failures and security regressions.
    """
    if not settings.BUGFLOW_URL:
        return {"changes": [], "source": "bugflow_unavailable"}
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.post(
                f"{settings.BUGFLOW_URL}/change_detection",
                json={"target": target},
            )
            r.raise_for_status()
            return {**r.json(), "source": "bugflow"}
    except Exception as e:
        logger.warning(f"[bridges/bugflow] surface_changes failed: {e}")
        return {"changes": [], "error": str(e)}


async def get_vulnerability_findings(target: str, severity: str = "high") -> list[dict]:
    """
    Pull vulnerability findings from BugFlow that warrant auto-ticketing.
    High/critical findings become ResilientAI tickets automatically.
    """
    if not settings.BUGFLOW_URL:
        return []
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.get(
                f"{settings.BUGFLOW_URL}/findings",
                params={"target": target, "severity": severity},
            )
            r.raise_for_status()
            return r.json().get("findings", [])
    except Exception as e:
        logger.warning(f"[bridges/bugflow] vulnerability_findings failed: {e}")
        return []


async def notify_threat_event(event: dict) -> bool:
    """
    Send a ThreatFade-detected event to BugFlow for its detection model.
    Bidirectional: BugFlow feeds ResilientAI, ResilientAI feeds BugFlow.
    """
    if not settings.BUGFLOW_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.BUGFLOW_URL}/threat_feed",
                json=event,
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/bugflow] notify_threat_event failed: {e}")
        return False


async def health_check() -> bool:
    if not settings.BUGFLOW_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.BUGFLOW_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
