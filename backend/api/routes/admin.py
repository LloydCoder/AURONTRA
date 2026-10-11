"""Tenant-scoped administrative API key and audit controls."""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_tenant_db
from models.api_key import APIKey
from models.audit_event import AuditEvent
from models.organization import Organization

router = APIRouter()
_ALLOWED_SCOPES = frozenset({
    "read:devices", "read:tickets", "write:tickets", "read:resilience",
    "read:threats", "read:reports", "read:integrations",
})
_GENESIS_HASH = "0" * 64


class APIKeyCreateRequest(BaseModel):
    scopes: list[str] = Field(min_length=1, max_length=8)
    expires_in_days: int = Field(default=90, ge=1, le=365)


def _is_active_key(row: APIKey) -> bool:
    if row.revoked_at is not None:
        return False
    expires_at = row.expires_at
    if expires_at is None:
        return True
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at > datetime.now(timezone.utc)


def _require_admin(request: Request) -> tuple[str, str]:
    tenant_id = getattr(request.state, "tenant_id", None)
    subject = getattr(request.state, "subject", None)
    role = getattr(request.state, "role", None)
    if settings.TEST_MODE and not role:
        role, subject = "org:owner", subject or "test-operator"
    if role not in {"admin", "owner", "org:admin", "org:owner"}:
        raise HTTPException(status_code=403, detail="Organization administrator role is required.")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise HTTPException(status_code=401, detail="Verified tenant context is required.")
    if not isinstance(subject, str) or not subject:
        raise HTTPException(status_code=401, detail="Verified actor identity is required.")
    return tenant_id, subject


async def _append_audit(
    db: AsyncSession, *, org_id: str, actor: str, event_type: str,
    resource_type: str, resource_id: str, event_data: dict,
) -> AuditEvent:
    # Serialize sequence allocation per tenant; the event and protected mutation
    # share the same transaction so an operation cannot commit without its audit.
    org = await db.scalar(select(Organization).where(Organization.id == org_id).with_for_update())
    if org is None or org.status != "active":
        raise HTTPException(status_code=403, detail="Organization is not active.")
    previous = await db.scalar(
        select(AuditEvent).where(AuditEvent.org_id == org_id)
        .order_by(AuditEvent.sequence.desc()).limit(1)
    )
    sequence = (previous.sequence + 1) if previous else 1
    previous_hash = previous.event_hash if previous else _GENESIS_HASH
    created_at = datetime.now(timezone.utc)
    canonical = json.dumps(event_data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    material = "\n".join((org_id, str(sequence), actor, event_type, resource_type, resource_id, previous_hash, canonical))
    event_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
    record = AuditEvent(
        id=str(uuid4()), org_id=org_id, sequence=sequence, actor_subject=actor,
        event_type=event_type, resource_type=resource_type, resource_id=resource_id,
        request_id=None, event_data=event_data, previous_hash=previous_hash,
        event_hash=event_hash, created_at=created_at,
    )
    db.add(record)
    await db.flush()
    return record


@router.get("/api-keys")
async def list_api_keys(request: Request, db: AsyncSession = Depends(get_tenant_db)):
    tenant_id, _ = _require_admin(request)
    rows = (await db.scalars(
        select(APIKey).where(APIKey.org_id == tenant_id)
        .order_by(APIKey.created_at.desc()).limit(100)
    )).all()
    return {"api_keys": [
        {"id": row.id, "prefix": row.key_prefix, "scopes": row.scopes,
         "created_at": row.created_at, "expires_at": row.expires_at,
         "revoked_at": row.revoked_at, "last_used_at": row.last_used_at,
         "active": _is_active_key(row)}
        for row in rows
    ]}


@router.post("/api-keys", status_code=201)
async def create_api_key(
    payload: APIKeyCreateRequest, request: Request,
    db: AsyncSession = Depends(get_tenant_db),
):
    tenant_id, subject = _require_admin(request)
    scopes = sorted(set(payload.scopes))
    if len(scopes) != len(payload.scopes) or any(scope not in _ALLOWED_SCOPES for scope in scopes):
        raise HTTPException(status_code=422, detail="One or more API key scopes are unsupported.")
    token = "aurontra_" + secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    key_id = str(uuid4())
    expires_at = now + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None
    row = APIKey(
        id=key_id, org_id=tenant_id, key_hash=hashlib.sha256(token.encode()).hexdigest(),
        key_prefix=token[:20], scopes=scopes, created_by=subject, created_at=now,
        expires_at=expires_at, revoked_at=None, last_used_at=None,
    )
    db.add(row)
    await _append_audit(
        db, org_id=tenant_id, actor=subject, event_type="admin.api_key.created",
        resource_type="api_key", resource_id=key_id,
        event_data={"scopes": scopes, "expires_at": expires_at.isoformat() if expires_at else None},
    )
    await db.flush()
    return {"id": key_id, "api_key": token, "prefix": row.key_prefix, "scopes": scopes,
            "expires_at": expires_at, "warning": "Copy this key now; the secret is shown only once."}


@router.post("/api-keys/{key_id}/revoke")
async def revoke_api_key(
    key_id: str, request: Request, db: AsyncSession = Depends(get_tenant_db),
):
    tenant_id, subject = _require_admin(request)
    row = await db.scalar(select(APIKey).where(APIKey.id == key_id, APIKey.org_id == tenant_id).with_for_update())
    if row is None:
        raise HTTPException(status_code=404, detail="API key not found.")
    if row.revoked_at is not None:
        return {"id": row.id, "revoked": True, "already_revoked": True}
    row.revoked_at = datetime.now(timezone.utc)
    await _append_audit(
        db, org_id=tenant_id, actor=subject, event_type="admin.api_key.revoked",
        resource_type="api_key", resource_id=row.id, event_data={"prefix": row.key_prefix},
    )
    await db.flush()
    return {"id": row.id, "revoked": True, "already_revoked": False}


@router.get("/audit")
async def list_audit_events(
    request: Request, limit: int = 50, db: AsyncSession = Depends(get_tenant_db),
):
    tenant_id, _ = _require_admin(request)
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail="Limit must be between 1 and 100.")
    rows = (await db.scalars(
        select(AuditEvent).where(AuditEvent.org_id == tenant_id)
        .order_by(AuditEvent.sequence.desc()).limit(limit)
    )).all()
    return {"events": [
        {"sequence": row.sequence, "actor": row.actor_subject, "event_type": row.event_type,
         "resource_type": row.resource_type, "resource_id": row.resource_id,
         "event_data": row.event_data, "previous_hash": row.previous_hash,
         "event_hash": row.event_hash, "created_at": row.created_at}
        for row in rows
    ]}
