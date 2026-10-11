"""Fail-closed pricing and durable provider webhook inbox."""
from __future__ import annotations
import hashlib
import json
import logging
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from billing.plans import PLANS, compute_monthly_cost
from billing.webhook_handler import verify_webhook_signature
from core.config import settings
from core.database import get_db
from models.webhook_event import WebhookEvent

router = APIRouter()
logger = logging.getLogger(__name__)
PROVIDER = "lemonsqueezy"
MAX_WEBHOOK_BYTES = 1_048_576
KNOWN_EVENTS = frozenset({"subscription_created", "subscription_updated", "subscription_payment_success", "subscription_cancelled", "subscription_expired"})


class EstimateRequest(BaseModel):
    plan: str
    device_count: int = Field(ge=1, le=100_000)
    annual: bool = True


class CheckoutRequest(BaseModel):
    plan: str
    device_count: int = Field(ge=1, le=100_000)
    org_id: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=3, max_length=254)


@router.get("/")
async def billing_overview(db: AsyncSession = Depends(get_db)):
    """Report durable inbox state, never process-local subscription state."""
    total = await db.scalar(select(func.count()).select_from(WebhookEvent).where(WebhookEvent.provider == PROVIDER))
    return {
        "status": "ok",
        "store_configured": bool(settings.LEMONSQUEEZY_STORE_ID),
        "checkout_enabled": False,
        "entitlement_grants_enabled": False,
        "durable_webhook_events": int(total or 0),
        "plans_available": list(PLANS.keys()),
    }


@router.get("/plans")
async def list_plans():
    """Return published pricing separately from live entitlement state."""
    return {"plans": [
        {"id": tier, "name": plan["name"], "price_per_device_annual": plan["price_per_device"],
         "price_per_device_monthly": plan.get("price_per_device_monthly", plan["price_per_device"]),
         "price_per_resolution": plan.get("price_per_resolution"),
         "annual_discount_pct": int(plan.get("annual_discount", 0) * 100), "features": plan["features"],
         "min_devices": plan.get("min_devices", 1), "max_devices": plan.get("max_devices")}
        for tier, plan in PLANS.items()
    ]}


@router.post("/estimate")
async def estimate_cost(payload: EstimateRequest):
    """Calculate a quote without creating a checkout session or entitlement."""
    try:
        monthly = compute_monthly_cost(payload.plan, payload.device_count, annual=payload.annual)
        undiscounted = compute_monthly_cost(payload.plan, payload.device_count, annual=False)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    annual_cost = round(monthly * 12, 2)
    return {"plan": payload.plan, "device_count": payload.device_count,
            "billing": "annual" if payload.annual else "monthly", "monthly_cost": monthly,
            "annual_cost": annual_cost,
            "savings": round((undiscounted - monthly) * 12, 2) if payload.annual else 0,
            "cost_per_device": round(monthly / payload.device_count, 2), "currency": "USD", "quote_only": True}


@router.post("/checkout", status_code=503)
async def create_checkout(payload: CheckoutRequest):
    """Fail closed until verified tenant context and provider checkout correlation exist."""
    raise HTTPException(status_code=503, detail=(
        "Checkout is disabled until authenticated tenant context, provider-created checkout sessions, "
        "durable event reconciliation, and entitlement tests are deployed."
    ))


@router.post("/webhook", status_code=202)
async def lemonsqueezy_webhook(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    """Authenticate and durably de-duplicate provider deliveries; never grant entitlements here."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_WEBHOOK_BYTES:
                raise HTTPException(status_code=413, detail="Webhook payload too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid content length") from None
    body = await request.body()
    if len(body) > MAX_WEBHOOK_BYTES:
        raise HTTPException(status_code=413, detail="Webhook payload too large")
    if not verify_webhook_signature(body, request.headers.get("X-Signature", "")):
        logger.warning("billing_webhook_rejected reason=invalid_signature")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from None
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Webhook payload must be an object")
    meta, data = payload.get("meta"), payload.get("data")
    if not isinstance(meta, dict) or not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Webhook envelope is invalid")
    event_name, object_id = meta.get("event_name"), data.get("id")
    if not isinstance(event_name, str) or not event_name or len(event_name) > 100:
        raise HTTPException(status_code=400, detail="Webhook event name is invalid")
    if not isinstance(object_id, (str, int)) or not str(object_id) or len(str(object_id)) > 255:
        raise HTTPException(status_code=400, detail="Webhook object ID is invalid")

    digest = hashlib.sha256(body).hexdigest()
    now = datetime.now(timezone.utc)
    known = event_name in KNOWN_EVENTS
    record = WebhookEvent(
        id=str(uuid4()), provider=PROVIDER, event_id=digest, org_id=None,
        payload_sha256=digest, status="received" if known else "ignored_unknown_event",
        payload_metadata={"event_name": event_name, "provider_object_id": str(object_id), "known_event": known},
        received_at=now, processed_at=None if known else now, last_error_code=None,
    )
    duplicate = False
    try:
        async with db.begin_nested():
            db.add(record)
            await db.flush()
    except IntegrityError:
        duplicate = True
        existing = await db.scalar(select(WebhookEvent).where(
            WebhookEvent.provider == PROVIDER, WebhookEvent.event_id == digest))
        if existing is None or existing.payload_sha256 != digest:
            logger.error("billing_webhook_idempotency_conflict provider=%s", PROVIDER)
            raise HTTPException(status_code=409, detail="Webhook idempotency conflict") from None
    if duplicate:
        response.headers["Idempotent-Replay"] = "true"
    logger.info("billing_webhook_accepted provider=%s event=%s duplicate=%s", PROVIDER, event_name, duplicate)
    return {"received": True, "duplicate": duplicate, "event": event_name,
            "entitlements_changed": False, "reconciliation_required": known}
