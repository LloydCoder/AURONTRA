"""
Billing router — Sprint 6.
LemonSqueezy webhook + plan management + real-time cost estimates.
Competitive gap: transparent pricing visible in-dashboard (vs NinjaOne opacity).
"""
import json
import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from billing.plans import PLANS, compute_monthly_cost
from billing.webhook_handler import verify_webhook_signature, process_webhook
from core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

# In-memory subscription store
_subscriptions: list[dict] = []


class EstimateRequest(BaseModel):
    plan: str
    device_count: int
    annual: bool = True


class CheckoutRequest(BaseModel):
    plan: str
    device_count: int
    org_id: str
    email: str


@router.get("/")
async def billing_overview():
    return {
        "status": "ok",
        "store_id": settings.LEMONSQUEEZY_STORE_ID,
        "active_subscriptions": len(_subscriptions),
        "plans_available": list(PLANS.keys()),
    }


@router.get("/plans")
async def list_plans():
    """Return all pricing plans with features. Full transparency."""
    return {
        "plans": [
            {
                "id": tier,
                "name": plan["name"],
                "price_per_device_annual": plan["price_per_device"],
                "price_per_device_monthly": plan.get("price_per_device_monthly", plan["price_per_device"]),
                "price_per_resolution": plan.get("price_per_resolution"),
                "annual_discount_pct": int(plan.get("annual_discount", 0) * 100),
                "features": plan["features"],
                "min_devices": plan.get("min_devices", 1),
                "max_devices": plan.get("max_devices"),
            }
            for tier, plan in PLANS.items()
        ]
    }


@router.post("/estimate")
async def estimate_cost(payload: EstimateRequest):
    """
    Real-time cost estimate. Competitive gap: no surprise billing.
    Shows exactly what you pay before checkout.
    """
    try:
        monthly = compute_monthly_cost(payload.plan, payload.device_count, annual=payload.annual)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    monthly_undiscounted = compute_monthly_cost(payload.plan, payload.device_count, annual=False)
    annual_cost = round(monthly * 12, 2)
    savings = round((monthly_undiscounted - monthly) * 12, 2) if payload.annual else 0

    return {
        "plan": payload.plan,
        "device_count": payload.device_count,
        "billing": "annual" if payload.annual else "monthly",
        "monthly_cost": monthly,
        "annual_cost": annual_cost,
        "savings": savings,
        "cost_per_device": round(monthly / payload.device_count, 2),
        "currency": "USD",
    }


@router.post("/checkout", status_code=503)
async def create_checkout(payload: CheckoutRequest):
    """Fail closed until provider-backed checkout and tenant authorization exist."""
    raise HTTPException(
        status_code=503,
        detail=(
            "Checkout is disabled until Aurontra has authenticated tenant context, "
            "provider-created checkout sessions, durable webhook idempotency, and entitlement reconciliation."
        ),
    )

@router.post("/webhook")
async def lemonsqueezy_webhook(request: Request):
    """
    LemonSqueezy webhook endpoint.
    Verifies HMAC-SHA256 signature then routes to handler.
    Events: subscription_created, subscription_updated, subscription_payment_success
    """
    body = await request.body()
    signature = request.headers.get("X-Signature", "")

    if not verify_webhook_signature(body, signature):
        logger.warning("[billing] Invalid webhook signature")
        raise HTTPException(status_code=400, detail="Invalid signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_name = payload.get("meta", {}).get("event_name", "unknown")
    data = payload.get("data", {})

    result = await process_webhook(event_name, data)
    _subscriptions.append(result)

    return {"received": True, "event": event_name, "result": result}
