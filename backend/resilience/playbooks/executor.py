"""
Playbook executor — central dispatcher for all self-healing playbooks.

Usage:
    result = await execute_playbook("disk_full", {"device_id": "srv-01", "disk_percent": 88})
    names  = list_playbooks()
"""
from datetime import datetime, timezone
from resilience.playbooks.base import normalize_device_id
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
    Build a recommendation from a named playbook; never execute actions.

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

    # Compatibility API: enforce the non-execution contract even if a future
    # playbook implementation returns contradictory legacy fields.
    created_at = result.get("created_at") or datetime.now(timezone.utc).isoformat()
    device_id, device_id_source = normalize_device_id(context)
    result["playbook"] = playbook_name
    result["device_id"] = device_id
    result["device_id_source"] = device_id_source
    result.setdefault("created_at", created_at)
    result["executed_at"] = created_at
    result["timestamp_semantics"] = "recommendation_created"
    result["status"] = "simulated"
    result["execution_mode"] = "recommendation_only"
    result["execution_enabled"] = False
    result["business_outcome_verified"] = False
    result["actions_taken"] = []
    if not isinstance(result.get("recommendations"), list):
        result["recommendations"] = []

    return result
