"""Tenant-scoped ticket APIs backed by durable SQLAlchemy persistence."""
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.ticket_resolver import resolve_ticket
from core.database import get_tenant_db
from ingestion.email_parser import parse_email
from ingestion.webhook import parse_webhook
from models.device import Device
from models.ticket import Ticket, TicketPriority, TicketSource, TicketStatus

router = APIRouter()


class TicketIngestRequest(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=20000)
    reporter_email: str = Field(min_length=3, max_length=320)
    source: Optional[str] = "manual"
    device_id: Optional[str] = Field(default=None, max_length=128)
    priority: Optional[str] = "medium"


class TicketResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    title: str
    description: str
    reporter_email: str
    source: str
    device_id: Optional[str] = None
    priority: str
    status: str
    ai_resolved: bool
    ai_response: Optional[str] = None
    escalated: bool = False
    created_at: Optional[datetime] = None


def _serialize(ticket: Ticket) -> dict:
    return {
        "id": ticket.id,
        "org_id": ticket.org_id,
        "title": ticket.title,
        "description": ticket.description,
        "reporter_email": ticket.reporter_email,
        "source": ticket.source.value if hasattr(ticket.source, "value") else ticket.source,
        "device_id": ticket.device_id,
        "priority": ticket.priority.value if hasattr(ticket.priority, "value") else ticket.priority,
        "status": ticket.status.value if hasattr(ticket.status, "value") else ticket.status,
        "ai_resolved": ticket.ai_resolved,
        "ai_response": ticket.ai_response,
        "escalated": (ticket.status == TicketStatus.ESCALATED),
        "created_at": ticket.created_at.isoformat() if ticket.created_at else None,
    }


def _enum_value(enum_type, value: Optional[str], default):
    if value is None:
        return default
    try:
        return enum_type(value.lower())
    except (ValueError, AttributeError):
        raise HTTPException(status_code=422, detail=f"Invalid {enum_type.__name__}: {value}")


async def _create_ticket(data: dict, request: Request, db: AsyncSession) -> Ticket:
    tenant_id = request.state.tenant_id
    device_id = data.get("device_id")
    if device_id:
        owned_device = await db.scalar(
            select(Device.id).where(Device.id == device_id, Device.org_id == tenant_id)
        )
        if owned_device is None:
            # Avoid revealing whether the device exists in another organization.
            raise HTTPException(status_code=404, detail="Device not found")
    source = _enum_value(TicketSource, data.get("source", "manual"), TicketSource.MANUAL)
    priority = _enum_value(TicketPriority, data.get("priority", "medium"), TicketPriority.MEDIUM)
    ticket = Ticket(
        id=f"tkt-{uuid.uuid4().hex}",
        org_id=tenant_id,
        title=data["title"],
        description=data.get("description", ""),
        reporter_email=data.get("reporter_email", ""),
        source=source,
        device_id=device_id,
        priority=priority,
        status=TicketStatus.OPEN,
        ai_resolved=False,
    )
    db.add(ticket)
    await db.flush()
    return ticket


@router.get("/")
async def list_tickets(request: Request, db: AsyncSession = Depends(get_tenant_db)):
    tenant_id = request.state.tenant_id
    result = await db.scalars(
        select(Ticket).where(Ticket.org_id == tenant_id).order_by(Ticket.created_at.desc(), Ticket.id)
    )
    tickets = [_serialize(item) for item in result.all()]
    return {"tickets": tickets, "total": len(tickets)}


@router.post("/ingest", status_code=201)
async def ingest_ticket(payload: TicketIngestRequest, request: Request, db: AsyncSession = Depends(get_tenant_db)):
    ticket = await _create_ticket(payload.model_dump(), request, db)
    return {"ticket": _serialize(ticket), "queued_for_ai_resolution": False,
            "queue_status": "not_queued_durable_job_pipeline_pending"}


@router.post("/ingest/email", status_code=201)
async def ingest_via_email(raw: dict, request: Request, db: AsyncSession = Depends(get_tenant_db)):
    try:
        parsed = parse_email(raw)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail="Invalid email ingestion payload") from exc
    parsed.setdefault("source", "email")
    ticket = await _create_ticket(parsed, request, db)
    return {"ticket": _serialize(ticket), "source": "email"}


@router.post("/ingest/webhook", status_code=201)
async def ingest_via_webhook(raw: dict, request: Request, db: AsyncSession = Depends(get_tenant_db)):
    try:
        parsed = parse_webhook(raw)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail="Invalid ticket webhook payload") from exc
    parsed["provider_source"] = parsed.get("source", "webhook")
    parsed["source"] = "webhook"
    ticket = await _create_ticket(parsed, request, db)
    return {"ticket": _serialize(ticket), "source": parsed["provider_source"]}


@router.post("/{ticket_id}/resolve")
async def resolve_ticket_endpoint(ticket_id: str, request: Request, db: AsyncSession = Depends(get_tenant_db)):
    ticket = await db.scalar(
        select(Ticket).where(Ticket.id == ticket_id, Ticket.org_id == request.state.tenant_id)
    )
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    result = await resolve_ticket(
        ticket_id=ticket.id,
        title=ticket.title,
        description=ticket.description,
        reporter_email=ticket.reporter_email,
        device_id=ticket.device_id,
    )
    ticket.ai_response = result.get("response")
    ticket.ai_model_used = result.get("model_used")
    confidence = result.get("confidence")
    ticket.ai_confidence = str(confidence) if confidence is not None else None
    # A generated answer is not evidence that the underlying IT issue was fixed.
    ticket.ai_resolved = False
    ticket.status = TicketStatus.ESCALATED if result.get("escalated") else TicketStatus.OPEN
    ticket.resolved_at = None
    await db.flush()
    return {
        **result,
        "resolved": False,
        "resolution_claimed_by_model": bool(result.get("resolved")),
        "outcome_verified": False,
        "ticket": _serialize(ticket),
    }


@router.get("/{ticket_id}")
async def get_ticket(ticket_id: str, request: Request, db: AsyncSession = Depends(get_tenant_db)):
    ticket = await db.scalar(
        select(Ticket).where(Ticket.id == ticket_id, Ticket.org_id == request.state.tenant_id)
    )
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return _serialize(ticket)
