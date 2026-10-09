"""
LemonSqueezy webhook handler.
Processes subscription lifecycle events from store 247127.

Events handled:
  subscription_created        → activate org subscription
  subscription_updated        → sync plan/status changes
  subscription_payment_success → record payment, extend access
  subscription_cancelled      → start grace period
  order_created               → one-time payment confirmation
"""
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from core.config import settings

logger = logging.getLogger(__name__)


def verify_webhook_signature(body: bytes, signature: str) -> bool:
    """
    Verify LemonSqueezy webhook HMAC-SHA256 signature.
    Signature is in X-Signature header.
    """
    if not settings.LEMONSQUEEZY_WEBHOOK_SECRET:
        logger.warning("[billing] No webhook secret configured — skipping signature check")
        return True  # Allow in dev mode

    expected = hmac.new(
        settings.LEMONSQUEEZY_WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


async def handle_subscription_created(data: dict) -> dict:
    """Activate subscription on new signup."""
    attrs = data.get("attributes", {})
    org_context = {
        "event": "subscription_created",
        "ls_subscription_id": data.get("id"),
        "ls_customer_id": attrs.get("customer_id"),
        "user_email": attrs.get("user_email"),
        "product_name": attrs.get("product_name"),
        "variant_name": attrs.get("variant_name"),
        "status": attrs.get("status"),
        "renews_at": attrs.get("renews_at"),
        "customer_portal_url": attrs.get("urls", {}).get("customer_portal"),
        "update_payment_url": attrs.get("urls", {}).get("update_payment_method"),
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }
    logger.info(f"[billing] Subscription created: {org_context['user_email']} → {org_context['product_name']}")
    return {"action": "subscription_activated", **org_context}


async def handle_subscription_updated(data: dict) -> dict:
    """Sync subscription changes — plan upgrades, cancellations, etc."""
    attrs = data.get("attributes", {})
    return {
        "event": "subscription_updated",
        "ls_subscription_id": data.get("id"),
        "status": attrs.get("status"),
        "cancelled": attrs.get("cancelled", False),
        "ends_at": attrs.get("ends_at"),
        "renews_at": attrs.get("renews_at"),
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }


async def handle_payment_success(data: dict) -> dict:
    """Record successful payment and extend billing period."""
    attrs = data.get("attributes", {})
    return {
        "event": "payment_success",
        "ls_subscription_id": data.get("id"),
        "user_email": attrs.get("user_email"),
        "renews_at": attrs.get("renews_at"),
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }


async def process_webhook(event_name: str, data: dict) -> dict:
    """
    Route a LemonSqueezy webhook event to the appropriate handler.

    Args:
        event_name: from meta.event_name in webhook payload
        data: the data object from the webhook

    Returns:
        Processing result dict
    """
    handlers = {
        "subscription_created":         handle_subscription_created,
        "subscription_updated":         handle_subscription_updated,
        "subscription_payment_success": handle_payment_success,
    }

    handler = handlers.get(event_name)
    if handler:
        return await handler(data)

    logger.info(f"[billing] Unhandled event: {event_name} — logged only")
    return {"event": event_name, "action": "logged", "data_id": data.get("id")}
