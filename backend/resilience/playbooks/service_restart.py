"""Service restart playbook — recommendation-only until a scoped agent exists."""
from resilience.playbooks.base import BasePlaybook

_DEFAULT_SERVICE = "application"
_SAFE_RESTARTABLE = {"nginx", "postgresql", "redis", "application", "api", "worker"}


class ServiceRestartPlaybook(BasePlaybook):
    name = "service_restart"

    async def execute(self, context: dict) -> dict:
        """Never call systemctl/sc from the API process."""
        service_name = context.get("service_name", _DEFAULT_SERVICE)
        approved_name = service_name in _SAFE_RESTARTABLE
        result = self._base_result(
            context,
            status="simulated" if approved_name else "approval_required",
            service_name=service_name,
            actions_taken=[
                "No service command was executed on the API host.",
                "Service restart requires an authenticated endpoint agent and an explicit target policy.",
            ],
            restart_successful=False,
            enforcement_verified=False,
            action_required="request_scoped_service_restart_approval" if approved_name else "review_unapproved_service_name",
        )
        await self.audit(context.get("device_id", "unknown"), result)
        return result
