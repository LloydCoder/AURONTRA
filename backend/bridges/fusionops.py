"""FusionOps bridge through the shared authenticated ecosystem client."""
from core.config import settings
from core.ecosystem_client import EcosystemIntegrationError, request_json


async def get_events(limit: int = 100) -> list:
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    result = await request_json(
        service="fusionops", base_url=settings.FUSIONOPS_URL,
        method="GET", path="/events", params={"limit": limit},
    )
    if not isinstance(result, list):
        raise EcosystemIntegrationError("bridge_response_contract_invalid", 502)
    return result


async def health_check() -> bool:
    try:
        result = await request_json(
            service="fusionops", base_url=settings.FUSIONOPS_URL,
            method="GET", path="/health", timeout_seconds=5,
        )
        return isinstance(result, dict) and result.get("status") in {"ok", "healthy"}
    except Exception:
        return False
