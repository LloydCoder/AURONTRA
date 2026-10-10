"""
LemonSqueezy webhook handler.
Webhook authenticity is mandatory. Missing configuration is a rejection,
not a development-mode bypass.
"""
import hashlib
import hmac
import logging
from datetime import datetime, timezone
from core.config import settings

logger = logging.getLogger(__name__)


def verify_webhook_signature(body: bytes, signature: str) -> bool:
    """Verify X-Signature HMAC-SHA256 over the exact raw request body."""
    secret = settings.LEMONSQUEEZY_WEBHOOK_SECRET
    if not secret or not signature:
        logger.error("[billing] Webhook rejected: signature verification is not configured")
        return False

    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


async def handle_subscription_created(data: dict) -> dict:
    """Record the verified subscription-created event."""
    attrs = data.get("attributes", {})
    context = {
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
    logger.info("[billing] Subscription created: subscription_id=%s", context["ls_subscription_id"])
    return {"action": "subscription_activated", **context}


async def handle_subscription_updated(data: dict) -> dict:
    """Record subscription status changes."""
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
    """Record a verified payment-success event."""
    attrs = data.get("attributes", {})
    return {
        "event": "payment_success",
        "ls_subscription_id": data.get("id"),
        "user_email": attrs.get("user_email"),
        "renews_at": attrs.get("renews_at"),
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }


async def process_webhook(event_name: str, data: dict) -> dict:
    """Route a verified provider event to its handler."""
    handlers = {
        "subscription_created": handle_subscription_created,
        "subscription_updated": handle_subscription_updated,
        "subscription_payment_success": handle_payment_success,
    }
    handler = handlers.get(event_name)
    if handler:
        return await handler(data)

    logger.info("[billing] Unhandled verified event: %s", event_name)
    return {"event": event_name, "action": "logged", "data_id": data.get("id")}
