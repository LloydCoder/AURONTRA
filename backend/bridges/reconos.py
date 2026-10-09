"""
ReconOS OFE Bridge — pulls device topology + temporal correlation data.
ReconOS: 6,277 lines, 129/129 tests, ArcadeDB graph, D3.js dashboard.

What flows IN from ReconOS:
  - Device relationship graph → DeviceTopology dashboard component
  - TemporalCorrelator results → enriches ResilientAI's failure prediction
  - Entity resolution → maps IPs to known assets
  - Confidence scores → weights resilience scoring
"""
import httpx
import logging
from core.config import settings

logger = logging.getLogger(__name__)


async def get_device_relationships(device_id: str) -> dict:
    """Pull device relationship graph for a given device from ReconOS."""
    if not settings.RECONOS_URL:
        return {"device_id": device_id, "relationships": [], "source": "reconos_unavailable"}
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.get(
                f"{settings.RECONOS_URL}/investigate/entity",
                params={"entity_id": device_id, "depth": 2},
            )
            r.raise_for_status()
            return {**r.json(), "source": "reconos"}
    except Exception as e:
        logger.warning(f"[bridges/reconos] get_device_relationships failed: {e}")
        return {"device_id": device_id, "relationships": [], "error": str(e)}


async def get_temporal_correlation(
    device_id: str,
    events: list[dict],
) -> dict:
    """
    Send device events to ReconOS TemporalCorrelator.
    Returns time-series correlation results to enrich ResilientAI's 72hr predictor.
    """
    if not settings.RECONOS_URL:
        return {"correlated": False, "source": "reconos_unavailable"}
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.post(
                f"{settings.RECONOS_URL}/correlate/temporal",
                json={"entity_id": device_id, "events": events},
            )
            r.raise_for_status()
            return {**r.json(), "source": "reconos"}
    except Exception as e:
        logger.warning(f"[bridges/reconos] temporal_correlation failed: {e}")
        return {"correlated": False, "error": str(e)}


async def get_infrastructure_map(org_id: str) -> dict:
    """
    Pull full infrastructure topology for an org from ReconOS.
    Used by the DeviceTopology dashboard component.
    """
    if not settings.RECONOS_URL:
        return {"nodes": [], "edges": [], "source": "reconos_unavailable"}
    try:
        async with httpx.AsyncClient(timeout=settings.BRIDGE_TIMEOUT) as client:
            r = await client.get(
                f"{settings.RECONOS_URL}/graph/topology",
                params={"org_id": org_id},
            )
            r.raise_for_status()
            return {**r.json(), "source": "reconos"}
    except Exception as e:
        logger.warning(f"[bridges/reconos] infrastructure_map failed: {e}")
        return {"nodes": [], "edges": [], "error": str(e)}


async def health_check() -> bool:
    if not settings.RECONOS_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.RECONOS_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
