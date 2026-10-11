"""ThreatFade bridge through the shared authenticated ecosystem client."""
from core.config import settings
from core.ecosystem_client import EcosystemIntegrationError, request_json
from core.tsic_contracts import TSICIdentityContext


async def detect_scenario(scenario: str, *, identity_context: TSICIdentityContext) -> dict:
    """Submit a detection scenario; non-idempotent POST is never automatically retried."""
    return await request_json(
        service="threatfade", base_url=settings.THREATFADE_URL,
        method="POST", path="/detect/scenario", payload={"scenario": scenario},
        identity_context=identity_context,
    )


async def detect_json(signals: dict, *, identity_context: TSICIdentityContext) -> dict:
    """Submit raw signal data for threat analysis."""
    return await request_json(
        service="threatfade", base_url=settings.THREATFADE_URL,
        method="POST", path="/detect/json", payload=signals,
        identity_context=identity_context,
    )


async def get_events(limit: int = 100, *, identity_context: TSICIdentityContext) -> list:
    """Fetch recent detection events from ThreatFade."""
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    result = await request_json(
        service="threatfade", base_url=settings.THREATFADE_URL,
        method="GET", path="/events", params={"limit": limit},
        identity_context=identity_context,
    )
    if not isinstance(result, list):
        raise EcosystemIntegrationError("bridge_response_contract_invalid", 502)
    return result


async def health_check() -> bool:
    """Return false on any configuration, authentication, transport or contract failure."""
    try:
        result = await request_json(
            service="threatfade", base_url=settings.THREATFADE_URL,
            method="GET", path="/health", timeout_seconds=5,
        )
        return isinstance(result, dict) and result.get("status") in {"ok", "healthy"}
    except Exception:
        return False
