"""SLA router."""
from fastapi import APIRouter
from datetime import datetime, timezone, timedelta
from sla.tracker import check_sla, sla_compliance_summary, SLA_TIERS

router = APIRouter()

@router.get("/status")
async def sla_status():
    return {
        "tiers": SLA_TIERS,
        "status": "active",
        "description": "SLA tracking active across all open tickets",
    }

@router.get("/compliance")
async def compliance():
    # Demo data until DB is wired
    sample = [
        {"priority": "high",   "created_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(), "resolved_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()},
        {"priority": "medium", "created_at": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(), "resolved_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()},
        {"priority": "low",    "created_at": (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat(), "resolved_at": datetime.now(timezone.utc).isoformat()},
    ]
    return sla_compliance_summary(sample)

@router.post("/check")
async def check(priority: str, created_at: str):
    dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    return check_sla(priority, dt)
