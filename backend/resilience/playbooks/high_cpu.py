"""High CPU playbook — recommendation-only until a scoped endpoint agent exists."""
from resilience.playbooks.base import BasePlaybook


class HighCPUPlaybook(BasePlaybook):
    name = "high_cpu"

    async def execute(self, context: dict) -> dict:
        """Do not inspect or reprioritize processes on the API host."""
        cpu_pct = context.get("cpu_percent")
        result = self._base_result(
            context,
            status="simulated",
            cpu_percent=cpu_pct,
            cpu_percent_source="caller_supplied_unverified" if cpu_pct is not None else "not_provided",
            processes_checked=0,
            top_processes=[],
            processes_niced=0,
            actions_taken=[],
            recommendations=[
                "No host processes were inspected or reprioritized.",
                "CPU remediation requires authenticated telemetry from the target device and a scoped action policy.",
            ],
            enforcement_verified=False,
            action_required="collect_authenticated_device_telemetry_and_review",
        )
        await self.audit(context.get("device_id", "unknown"), result)
        return result
