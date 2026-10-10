"""
Automation router — safety baseline.

Playbook execution is intentionally disabled at the public API boundary until
tenant authorization, approvals, and authenticated endpoint-agent execution
are implemented and verified. Listing playbooks is informational only.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from resilience.playbooks.executor import list_playbooks

router = APIRouter()
_EXECUTION_DISABLED_DETAIL = (
    "Self-healing execution is disabled pending authenticated endpoint-agent "
    "execution, tenant authorization, policy enforcement, and postcondition verification."
)


class TriggerRequest(BaseModel):
    playbook_name: str
    device_id: str
    context: Optional[dict] = None


@router.get("/")
async def automation_overview():
    return {"status": "restricted", "execution_enabled": False, "rules": [], "executions_today": 0}


@router.get("/playbooks")
async def list_available_playbooks():
    """List registered playbooks without authorizing their execution."""
    names = list_playbooks()
    return {
        "playbooks": names,
        "count": len(names),
        "execution_enabled": False,
        "execution_disabled_reason": _EXECUTION_DISABLED_DETAIL,
        "descriptions": {
            "disk_full": "Disk cleanup workflow (execution disabled pending safe path allowlisting)",
            "service_restart": "Service restart workflow (execution disabled pending endpoint agent)",
            "cert_expiry": "Certificate workflow (execution disabled pending domain/egress controls)",
            "high_cpu": "High CPU workflow (execution disabled pending endpoint agent)",
        },
    }


@router.post("/trigger", status_code=503)
async def trigger_playbook(payload: TriggerRequest):
    """Reject public execution until the governed endpoint path is complete."""
    # Never call execute_playbook here: current playbooks may affect the API
    # host, and payload.device_id does not prove a remote device was targeted.
    raise HTTPException(status_code=503, detail=_EXECUTION_DISABLED_DETAIL)


@router.get("/history")
async def execution_history(limit: int = 50):
    """Report that durable execution history is unavailable."""
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    return {
        "executions": [],
        "total": 0,
        "history_enabled": False,
        "reason": "Durable execution history is not implemented yet.",
    }
