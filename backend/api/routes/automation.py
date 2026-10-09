"""
Automation router — Sprint 5.
Trigger self-healing playbooks manually or via rule conditions.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from resilience.playbooks.executor import execute_playbook, list_playbooks

router = APIRouter()

# In-memory execution history
_executions: list[dict] = []


class TriggerRequest(BaseModel):
    playbook_name: str
    device_id: str
    context: Optional[dict] = {}


@router.get("/")
async def automation_overview():
    return {
        "status": "ok",
        "rules": [],
        "executions_today": len(_executions),
    }


@router.get("/playbooks")
async def list_available_playbooks():
    """List all registered self-healing playbooks."""
    names = list_playbooks()
    return {
        "playbooks": names,
        "count": len(names),
        "descriptions": {
            "disk_full":       "Clears temp files, rotates logs, frees disk space",
            "service_restart": "Gracefully restarts a named system service",
            "cert_expiry":     "Renews SSL certificate via certbot for a domain",
            "high_cpu":        "Identifies and renice-s runaway CPU processes",
        },
    }


@router.post("/trigger", status_code=201)
async def trigger_playbook(payload: TriggerRequest):
    """Manually trigger a self-healing playbook on a device."""
    context = {**(payload.context or {}), "device_id": payload.device_id}
    try:
        result = await execute_playbook(payload.playbook_name, context)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    _executions.append(result)
    return result


@router.get("/history")
async def execution_history(limit: int = 50):
    """Return recent playbook execution history."""
    return {
        "executions": _executions[-limit:],
        "total": len(_executions),
    }
