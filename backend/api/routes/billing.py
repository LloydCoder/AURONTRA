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
from billing.plans import PLANS, compute_monthly_cost, get_plan_for_device_count
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


@router.post("/checkout")
async def create_checkout(payload: CheckoutRequest):
    """
    Generate a LemonSqueezy checkout URL for a given plan.
    Pre-fills org context in checkout metadata.
    """
    if payload.plan not in PLANS:
        raise HTTPException(status_code=422, detail=f"Unknown plan: {payload.plan}")

    plan = PLANS[payload.plan]
    variant_id = plan.get("ls_variant_id", "")

    # Build checkout URL with pre-filled metadata
    # In production: call LemonSqueezy API to create a checkout session
    # For now: construct URL with query params
    checkout_url = (
        f"{settings.LS_CHECKOUT_BASE_URL}/buy/{variant_id}"
        f"?checkout[email]={payload.email}"
        f"&checkout[custom][org_id]={payload.org_id}"
        f"&checkout[custom][device_count]={payload.device_count}"
        if variant_id
        else f"https://resilientai.lemonsqueezy.com/checkout?plan={payload.plan}&org={payload.org_id}"
    )

    monthly = compute_monthly_cost(payload.plan, payload.device_count, annual=True)

    return {
        "checkout_url": checkout_url,
        "plan": payload.plan,
        "device_count": payload.device_count,
        "monthly_cost_usd": monthly,
        "org_id": payload.org_id,
        "note": "You will be redirected to LemonSqueezy to complete payment.",
    }


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
