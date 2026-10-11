"""Durable tenant-bound billing checkout intents and provider subscription state."""
from sqlalchemy import (
    CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, JSON,
    String, UniqueConstraint, func,
)
from core.database import Base


class BillingCheckoutIntent(Base):
    __tablename__ = "billing_checkout_intents"
    __table_args__ = (
        UniqueConstraint("org_id", "idempotency_key", name="uq_billing_checkout_org_idempotency"),
        UniqueConstraint("provider", "provider_checkout_id", name="uq_billing_checkout_provider_checkout"),
        CheckConstraint(
            "status IN ('creating','pending','unknown_outcome','completed','cancelled','expired','failed')",
            name="ck_billing_checkout_intent_status",
        ),
        CheckConstraint("device_count > 0", name="ck_billing_checkout_device_count_positive"),
        Index("ix_billing_checkout_org_status_created", "org_id", "status", "created_at"),
    )

    id = Column(String(36), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    provider = Column(String(32), nullable=False, default="lemonsqueezy", server_default="lemonsqueezy")
    provider_checkout_id = Column(String(128), nullable=True)
    idempotency_key = Column(String(128), nullable=False)
    plan_id = Column(String(32), nullable=False)
    variant_id = Column(String(64), nullable=False)
    device_count = Column(Integer, nullable=False)
    status = Column(String(32), nullable=False, default="creating", server_default="creating")
    checkout_url = Column(String(2048), nullable=True)
    provider_subscription_id = Column(String(128), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    last_error_code = Column(String(100), nullable=True)


class BillingSubscription(Base):
    __tablename__ = "billing_subscriptions"
    __table_args__ = (
        UniqueConstraint("provider", "provider_subscription_id", name="uq_billing_subscription_provider_id"),
        CheckConstraint(
            "status IN ('active','on_trial','past_due','paused','unpaid','cancelled','expired','unknown')",
            name="ck_billing_subscription_status",
        ),
        Index("ix_billing_subscription_org_status", "org_id", "status"),
    )

    id = Column(String(36), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    checkout_intent_id = Column(String(36), ForeignKey("billing_checkout_intents.id", ondelete="RESTRICT"), nullable=False)
    provider = Column(String(32), nullable=False, default="lemonsqueezy", server_default="lemonsqueezy")
    provider_subscription_id = Column(String(128), nullable=False)
    provider_customer_id = Column(String(128), nullable=True)
    plan_id = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default="unknown", server_default="unknown")
    renews_at = Column(DateTime(timezone=True), nullable=True)
    ends_at = Column(DateTime(timezone=True), nullable=True)
    provider_updated_at = Column(DateTime(timezone=True), nullable=True)
    provider_metadata = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
