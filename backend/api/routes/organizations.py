"""Tenant organization lifecycle endpoints.

Offboarding is a controlled administrative state transition, not destructive
deletion. The authenticated endpoint-agent protocol is implemented in Phase 08;
provisioned devices remain inactive until that protocol is completed.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_tenant_db_lifecycle
from models.device import Device
from models.organization import Organization

router = APIRouter()


class OrganizationView(BaseModel):
    id: str
    name: str
    status: str


@router.get("/me")
async def get_current_organization(
    request: Request,
    db: AsyncSession = Depends(get_tenant_db_lifecycle),
):
    org = await db.get(Organization, request.state.tenant_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return {"id": org.id, "name": org.name, "status": org.status}


@router.post("/offboard")
async def offboard_organization(
    request: Request,
    db: AsyncSession = Depends(get_tenant_db_lifecycle),
):
    """Disable the tenant and every provisioned endpoint without deleting evidence."""
    org = await db.scalar(
        select(Organization)
        .where(Organization.id == request.state.tenant_id)
        .with_for_update()
    )
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if org.status == "offboarded":
        return {"organization_id": org.id, "status": "offboarded", "already_offboarded": True}

    now = datetime.now(timezone.utc)
    org.status = "offboarded"
    await db.execute(
        update(Device)
        .where(Device.org_id == org.id)
        .values(is_active=False, revoked_at=now)
    )
    await db.flush()
    return {
        "organization_id": org.id,
        "status": "offboarded",
        "devices_revoked": True,
        "evidence_retained": True,
    }
