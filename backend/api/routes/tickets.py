"""
Tickets router — Sprint 2.
Ingest via direct POST, email, or webhook.
Resolve via AI agent.
"""
import uuid
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from agents.ticket_resolver import resolve_ticket
from ingestion.email_parser import parse_email
from ingestion.webhook import parse_webhook

router = APIRouter()
_tickets: list[dict] = []


class TicketIngestRequest(BaseModel):
    title: str
    description: str
    reporter_email: str
    source: Optional[str] = "manual"
    device_id: Optional[str] = None
    priority: Optional[str] = "medium"


def _make_ticket(data: dict) -> dict:
    return {
        "id": f"tkt-{uuid.uuid4().hex[:8]}",
        "title": data.get("title", "Untitled"),
        "description": data.get("description", ""),
        "reporter_email": data.get("reporter_email", ""),
        "source": data.get("source", "manual"),
        "device_id": data.get("device_id"),
        "priority": data.get("priority", "medium"),
        "status": "open",
        "ai_resolved": False,
        "ai_response": None,
        "escalated": False,
    }


@router.get("/")
async def list_tickets():
    return {"tickets": _tickets, "total": len(_tickets)}


@router.post("/ingest", status_code=201)
async def ingest_ticket(payload: TicketIngestRequest):
    ticket = _make_ticket(payload.model_dump())
    _tickets.append(ticket)
    return {"ticket": ticket, "queued_for_ai_resolution": True}


@router.post("/ingest/email", status_code=201)
async def ingest_via_email(raw: dict):
    try:
        parsed = parse_email(raw)
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=422, detail=str(e))
    ticket = _make_ticket(parsed)
    _tickets.append(ticket)
    return {"ticket": ticket, "source": "email"}


@router.post("/ingest/webhook", status_code=201)
async def ingest_via_webhook(raw: dict):
    try:
        parsed = parse_webhook(raw)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    ticket = _make_ticket(parsed)
    _tickets.append(ticket)
    return {"ticket": ticket, "source": parsed.get("source")}


@router.post("/{ticket_id}/resolve")
async def resolve_ticket_endpoint(ticket_id: str):
    ticket = next((t for t in _tickets if t["id"] == ticket_id), None)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    result = await resolve_ticket(
        ticket_id=ticket_id,
        title=ticket["title"],
        description=ticket["description"],
        reporter_email=ticket["reporter_email"],
        device_id=ticket.get("device_id"),
    )
    ticket["ai_resolved"] = result["resolved"]
    ticket["ai_response"] = result["response"]
    ticket["escalated"] = result["escalated"]
    ticket["status"] = "resolved" if result["resolved"] else (
        "escalated" if result["escalated"] else "open"
    )
    return result


@router.get("/{ticket_id}")
async def get_ticket(ticket_id: str):
    ticket = next((t for t in _tickets if t["id"] == ticket_id), None)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket
