"""
Onboarding router — Sprint 6.
One-click org registration with instant agent install command.
Competitive gap: eliminates NinjaOne's "multi-tenant email friction".
"""
from fastapi import APIRouter
from pydantic import BaseModel
from onboarding.service import register_organisation

router = APIRouter()


class RegisterRequest(BaseModel):
    org_name: str
    admin_email: str
    plan: str = "business"
    device_count: int = 10


@router.post("/register", status_code=201)
async def register(payload: RegisterRequest):
    """
    Register a new organisation.
    Returns org_id, api_key, and one-line agent install command.
    """
    result = register_organisation(
        org_name=payload.org_name,
        admin_email=payload.admin_email,
        plan=payload.plan,
        device_count=payload.device_count,
    )
    return result


@router.get("/health")
async def onboarding_health():
    return {"status": "ok", "service": "onboarding"}
