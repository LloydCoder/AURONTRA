"""FusionOps bridge — orchestration layer on AWS EC2 Stockholm."""
import httpx
from core.config import settings


async def get_events(limit: int = 100) -> list:
    async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
        r = await client.get(f"{settings.FUSIONOPS_URL}/events?limit={limit}")
        r.raise_for_status()
        return r.json()


async def health_check() -> bool:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.FUSIONOPS_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
