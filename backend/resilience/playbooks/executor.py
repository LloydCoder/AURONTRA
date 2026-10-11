"""
Playbook executor — central dispatcher for all self-healing playbooks.

Usage:
    result = await execute_playbook("disk_full", {"device_id": "srv-01", "disk_percent": 88})
    names  = list_playbooks()
"""
from datetime import datetime, timezone
from resilience.playbooks.disk_full import DiskFullPlaybook
from resilience.playbooks.service_restart import ServiceRestartPlaybook
from resilience.playbooks.cert_expiry import CertExpiryPlaybook
from resilience.playbooks.high_cpu import HighCPUPlaybook

_REGISTRY = {
    "disk_full":       DiskFullPlaybook,
    "service_restart": ServiceRestartPlaybook,
    "cert_expiry":     CertExpiryPlaybook,
    "high_cpu":        HighCPUPlaybook,
}


def list_playbooks() -> list[str]:
    """Return the names of all registered self-healing playbooks."""
    return list(_REGISTRY.keys())


async def execute_playbook(playbook_name: str, context: dict) -> dict:
    """
    Execute a named self-healing playbook.

    Args:
        playbook_name: one of disk_full | service_restart | cert_expiry | high_cpu
        context: trigger context dict (device_id + playbook-specific fields)

    Returns:
        Execution result dict with status, playbook, device_id, executed_at

    Raises:
        ValueError: if playbook_name is not in the registry
    """
    if playbook_name not in _REGISTRY:
        raise ValueError(
            f"Unknown playbook '{playbook_name}'. "
            f"Available: {', '.join(_REGISTRY.keys())}"
        )

    playbook_cls = _REGISTRY[playbook_name]
    playbook = playbook_cls()

    result = await playbook.execute(context)

    # Compatibility API: this dispatcher only builds recommendations. It is
    # not an execution authority and must never claim a verified outcome.
    result.setdefault("playbook", playbook_name)
    result.setdefault("device_id", context.get("device_id", "unknown"))
    result.setdefault("executed_at", datetime.now(timezone.utc).isoformat())
    result.setdefault("status", "simulated")
    result.setdefault("execution_mode", "recommendation_only")
    result.setdefault("execution_enabled", False)
    result.setdefault("business_outcome_verified", False)

    return result
