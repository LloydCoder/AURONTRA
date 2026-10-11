"""Base recommendation planner — playbooks never execute local side effects."""
from abc import ABC, abstractmethod
from datetime import datetime, timezone
import logging
import re

logger = logging.getLogger(__name__)


class BasePlaybook(ABC):
    name: str = "base"

    @abstractmethod
    async def execute(self, context: dict) -> dict:
        """
        Build a recommendation only; this method must not perform side effects.

        Args:
            context: untrusted legacy input; never sufficient to authorize execution

        Returns:
            Result envelope explicitly marked recommendation-only and unverified.
        """
        raise NotImplementedError

    async def audit(self, device_id: str, result: dict) -> None:
        """Log minimal recommendation metadata; this is not authoritative audit evidence."""
        safe_device_id = device_id if isinstance(device_id, str) and re.fullmatch(r"[A-Za-z0-9:_-]{1,64}", device_id) else "unknown"
        logger.info(
            "playbook_recommendation name=%s device=%s status=%s at=%s",
            self.name,
            safe_device_id,
            result.get("status"),
            datetime.now(timezone.utc).isoformat(),
        )

    def _base_result(self, context: dict, **kwargs) -> dict:
        """Build the standard result envelope."""
        created_at = datetime.now(timezone.utc).isoformat()
        return {
            "playbook": self.name,
            "device_id": context.get("device_id", "unknown"),
            "created_at": created_at,
            "executed_at": created_at,
            "timestamp_semantics": "recommendation_created",
            "status": "simulated",
            "execution_mode": "recommendation_only",
            "execution_enabled": False,
            "business_outcome_verified": False,
            **kwargs,
        }
