"""
TwinGuard Bridge — AI containment verdicts → ResilientAI threat events.
TwinGuard: NVIDIA OpenShell/NemoClaw, Parliament Ensemble, 22 modules,
5 defense layers, React GUI, domain twinguard.ai.
ThreatFade feeds TwinGuard as the network threat oracle.

What flows IN from TwinGuard:
  - AI containment verdicts → creates threat events in ResilientAI
  - Boundary violation alerts → high-priority tickets
  - Parliament Ensemble decisions → enriches threat scoring

What flows OUT to TwinGuard:
  - ThreatFade C2 detections → TwinGuard's threat model
  - Network anomaly signals → TwinGuard's 5 defense layers
"""
import httpx
import logging
from core.config import settings

logger = logging.getLogger(__name__)


async def receive_containment_verdict(verdict: dict) -> dict:
    """
    Process an AI containment verdict from TwinGuard.
    Converts it to a ResilientAI threat event for blocking + SIEM export.
    """
    threat_level_map = {
        "contained":    "high",
        "boundary_violation": "critical",
        "safe":         "info",
        "suspicious":   "medium",
    }

    verdict_status = verdict.get("status", "safe")
    return {
        "source": "twinguard",
        "event_type": "ai_containment_verdict",
        "threat_level": threat_level_map.get(verdict_status, "medium"),
        "auto_block": verdict_status in ("contained", "boundary_violation"),
        "mitre_ttp": "T1059",  # Command and Scripting Interpreter
        "detail": verdict.get("detail", ""),
        "model_name": verdict.get("model_name", "unknown"),
        "parliament_consensus": verdict.get("consensus", {}),
    }


async def send_threat_signal(signal: dict) -> bool:
    """
    Forward ThreatFade C2 detections to TwinGuard's 5-layer defense system.
    TwinGuard uses these to update its Parliament Ensemble threat model.
    """
    if not settings.TWINGUARD_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.post(
                f"{settings.TWINGUARD_URL}/threats/ingest",
                json={
                    **signal,
                    "source": "resilientai_threatfade",
                },
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/twinguard] send_threat_signal failed: {e}")
        return False


async def get_parliament_decision(scenario: str) -> dict:
    """
    Query TwinGuard's Parliament Ensemble (Claude+Grok+ThreatFade voting)
    for a threat classification decision.
    Used to strengthen ResilientAI's auto-block confidence.
    """
    if not settings.TWINGUARD_URL:
        return {"decision": "unavailable", "confidence": 0, "source": "twinguard_unavailable"}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                f"{settings.TWINGUARD_URL}/parliament/decide",
                json={"scenario": scenario, "requester": "resilientai"},
            )
            r.raise_for_status()
            return {**r.json(), "source": "twinguard"}
    except Exception as e:
        logger.warning(f"[bridges/twinguard] parliament_decision failed: {e}")
        return {"decision": "error", "confidence": 0, "error": str(e)}


async def health_check() -> bool:
    if not settings.TWINGUARD_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.TWINGUARD_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
