"""Base recommendation planner — playbooks never execute local side effects."""
from abc import ABC, abstractmethod
from datetime import datetime, timezone
import logging

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
        logger.info(
            f"[playbook:{self.name}] device={device_id} "
            f"status={result.get('status')} "
            f"at={datetime.now(timezone.utc).isoformat()}"
        )

    def _base_result(self, context: dict, **kwargs) -> dict:
        """Build the standard result envelope."""
        return {
            "playbook": self.name,
            "device_id": context.get("device_id", "unknown"),
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "status": "simulated",
            "execution_mode": "recommendation_only",
            "execution_enabled": False,
            "business_outcome_verified": False,
            **kwargs,
        }
