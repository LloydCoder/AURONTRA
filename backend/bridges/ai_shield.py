"""
AI Shield Bridge — security incidents → ResilientAI threat events.
AI Shield: Sprint 1 complete, Parliament Ensemble (Claude+Grok+ThreatFade),
MITRE ATLAS coverage, 136 tests.
Deployed on port 8002 on AWS EC2 Stockholm.

What flows IN from AI Shield:
  - Security incidents detected → creates threat events in ResilientAI
  - MITRE ATLAS findings → enriches threat classification
  - Parliament Ensemble verdicts → high-confidence blocking decisions

What flows OUT to AI Shield:
  - ThreatFade C2 events → AI Shield's threat intelligence
  - Blocked IPs/signatures → AI Shield's blocklist
"""
import httpx
import logging
from core.config import settings

logger = logging.getLogger(__name__)


async def receive_security_incident(incident: dict) -> dict:
    """
    Process a security incident from AI Shield.
    Maps it to a ResilientAI threat event for blocking + SLA tracking.
    """
    severity_map = {
        "critical": "critical",
        "high":     "high",
        "medium":   "medium",
        "low":      "low",
        "info":     "info",
    }
    return {
        "source": "ai_shield",
        "event_type": "ai_security_incident",
        "threat_level": severity_map.get(incident.get("severity", "medium"), "medium"),
        "mitre_atlas": incident.get("mitre_atlas_ttp", ""),
        "mitre_ttp": incident.get("mitre_ttp", "T1059"),
        "auto_block": incident.get("severity") in ("critical", "high"),
        "detail": incident.get("description", ""),
        "parliament_verdict": incident.get("parliament_verdict", {}),
        "affected_model": incident.get("model_name", ""),
    }


async def send_threatfade_event(event: dict) -> bool:
    """
    Forward a ThreatFade detection to AI Shield's threat intelligence feed.
    AI Shield uses this to update its 11 injection detection patterns.
    """
    if not settings.AI_SHIELD_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.AI_SHIELD_URL}/threats/ingest",
                json={**event, "source": "resilientai_threatfade"},
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/ai_shield] send_threatfade_event failed: {e}")
        return False


async def send_blocked_ip(ip: str, reason: str, z_score: float) -> bool:
    """
    Notify AI Shield of a blocked IP so it updates its runtime blocklist.
    AI Shield's ThreatFade integration runs on every chatbot message —
    this keeps it current with network-layer blocks.
    """
    if not settings.AI_SHIELD_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.AI_SHIELD_URL}/blocklist/add",
                json={"ip": ip, "reason": reason, "z_score": z_score,
                      "source": "resilientai"},
            )
            return r.status_code in (200, 201)
    except Exception as e:
        logger.warning(f"[bridges/ai_shield] send_blocked_ip failed: {e}")
        return False


async def health_check() -> bool:
    if not settings.AI_SHIELD_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.AI_SHIELD_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
