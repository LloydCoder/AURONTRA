"""Base playbook executor — all self-healing playbooks inherit from this."""
from abc import ABC, abstractmethod
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


class BasePlaybook(ABC):
    name: str = "base"

    @abstractmethod
    async def execute(self, context: dict) -> dict:
        """
        Execute the playbook.

        Args:
            context: dict with device_id and trigger-specific fields

        Returns:
            Result dict with at minimum: status, playbook, device_id, executed_at
        """
        raise NotImplementedError

    async def audit(self, device_id: str, result: dict) -> None:
        """Log execution to audit trail."""
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
            "status": "executed",
            **kwargs,
        }
