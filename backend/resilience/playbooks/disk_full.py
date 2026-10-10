"""Disk pressure playbook — recommendation-only until a scoped agent exists."""
from resilience.playbooks.base import BasePlaybook


class DiskFullPlaybook(BasePlaybook):
    name = "disk_full"

    async def execute(self, context: dict) -> dict:
        """Never delete host files; return a safe recommendation only."""
        disk_pct = context.get("disk_percent")
        result = self._base_result(
            context,
            status="simulated",
            disk_percent_before=disk_pct,
            actions_taken=[
                "No filesystem changes were made.",
                "Cleanup requires an authenticated endpoint agent and an explicit app-owned path allowlist.",
                "Recommendation: inspect filesystem usage and propose cleanup candidates for approval.",
            ],
            bytes_freed=0,
            space_freed_mb=0.0,
            enforcement_verified=False,
            action_required="review_disk_usage_and_approve_scoped_cleanup",
        )
        await self.audit(context.get("device_id", "unknown"), result)
        return result
