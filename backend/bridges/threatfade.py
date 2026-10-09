"""ThreatFade bridge — calls existing ThreatFade/FusionOps API on AWS EC2 Stockholm."""
import httpx
from core.config import settings


async def detect_scenario(scenario: str) -> dict:
    """Run a named threat detection scenario through ThreatFade."""
    async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
        r = await client.post(
            f"{settings.THREATFADE_URL}/detect/scenario",
            json={"scenario": scenario},
        )
        r.raise_for_status()
        return r.json()


async def detect_json(signals: dict) -> dict:
    """Submit raw signal data for threat analysis."""
    async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
        r = await client.post(
            f"{settings.THREATFADE_URL}/detect/json",
            json=signals,
        )
        r.raise_for_status()
        return r.json()


async def get_events(limit: int = 100) -> list:
    """Fetch the last N detection events from ThreatFade."""
    async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
        r = await client.get(f"{settings.THREATFADE_URL}/events?limit={limit}")
        r.raise_for_status()
        return r.json()


async def health_check() -> bool:
    """Ping ThreatFade health endpoint. Returns True if reachable."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.THREATFADE_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
