"""Idempotency ledger for authenticated external webhook deliveries."""
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, UniqueConstraint, func
from core.database import Base


class WebhookEvent(Base):
    __tablename__ = "webhook_events"
    __table_args__ = (
        UniqueConstraint("provider", "event_id", name="uq_webhook_provider_event"),
    )

    id = Column(String(64), primary_key=True)
    provider = Column(String(80), nullable=False)
    event_id = Column(String(255), nullable=False)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True)
    payload_sha256 = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="received", index=True)
    payload_metadata = Column(JSON, nullable=False, default=dict)
    received_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    processed_at = Column(DateTime(timezone=True), nullable=True)
    last_error_code = Column(String(100), nullable=True)

    def __repr__(self) -> str:
        return f"<WebhookEvent {self.provider}:{self.event_id} [{self.status}]>"
