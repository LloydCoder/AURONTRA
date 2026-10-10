"""
Onboarding router — restricted until secure organization lifecycle is implemented.
Public registration must not mint tenant credentials or expose an unverified installer.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class RegisterRequest(BaseModel):
    org_name: str
    admin_email: str
    plan: str = "business"
    device_count: int = 10


@router.post("/register", status_code=503)
async def register(payload: RegisterRequest):
    """Reject registration until identity, persistence, and key lifecycle are secure."""
    raise HTTPException(
        status_code=503,
        detail=(
            "Organization registration is disabled until authenticated organization lifecycle, "
            "durable tenant records, hashed/rotatable API keys, and signed agent installation are implemented."
        ),
    )


@router.get("/health")
async def onboarding_health():
    return {"status": "ok", "service": "onboarding", "registration_enabled": False}
