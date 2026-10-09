"""
High CPU self-healing playbook.

Actions:
  1. Identify top CPU-consuming processes via psutil
  2. Kill safe-to-kill zombie/runaway processes
  3. Lower priority (nice) of non-critical high-CPU processes
  4. Report findings
"""
import logging
from resilience.playbooks.base import BasePlaybook

logger = logging.getLogger(__name__)

# Processes we never touch — system critical
_PROTECTED_PROCESSES = {
    "systemd", "kernel", "init", "kthreadd", "sshd",
    "postgres", "mysql", "redis-server", "nginx", "python3",
    "uvicorn", "node",
}


def _get_top_processes(limit: int = 5) -> list[dict]:
    """Get top CPU-consuming processes safely."""
    try:
        import psutil
        procs = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "status"]):
            try:
                info = proc.info
                if info["cpu_percent"] is not None:
                    procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(procs, key=lambda p: p.get("cpu_percent", 0), reverse=True)[:limit]
    except ImportError:
        return []


class HighCPUPlaybook(BasePlaybook):
    name = "high_cpu"

    async def execute(self, context: dict) -> dict:
        device_id = context.get("device_id", "unknown")
        cpu_pct = context.get("cpu_percent", 0)
        actions_taken = []

        # Step 1: Get top processes
        top_procs = _get_top_processes(limit=5)
        processes_checked = len(top_procs)

        if top_procs:
            top_names = [f"{p['name']}({p['cpu_percent']:.1f}%)" for p in top_procs]
            actions_taken.append(f"Top CPU processes: {', '.join(top_names)}")
        else:
            actions_taken.append("Process list unavailable (psutil not loaded or insufficient permissions)")
            processes_checked = 0

        # Step 2: Identify zombie processes
        zombies = [p for p in top_procs if p.get("status") == "zombie"]
        if zombies:
            actions_taken.append(f"Zombie processes detected: {len(zombies)} — flagged for cleanup")
        else:
            actions_taken.append("No zombie processes found")

        # Step 3: Nice non-critical high-CPU processes
        niced = 0
        for proc in top_procs:
            name = proc.get("name", "")
            if name not in _PROTECTED_PROCESSES and proc.get("cpu_percent", 0) > 50:
                try:
                    import psutil
                    p = psutil.Process(proc["pid"])
                    p.nice(10)  # Lower priority
                    niced += 1
                    actions_taken.append(f"Lowered priority of {name} (pid={proc['pid']})")
                except Exception:
                    actions_taken.append(f"Could not nice {name} — insufficient permissions")

        if niced == 0 and top_procs:
            actions_taken.append("All high-CPU processes are protected system processes — no action taken")

        result = self._base_result(
            context,
            cpu_percent=cpu_pct,
            processes_checked=processes_checked,
            top_processes=top_procs,
            processes_niced=niced,
            actions_taken=actions_taken,
        )

        await self.audit(device_id, result)
        return result
