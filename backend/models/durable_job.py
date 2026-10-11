"""Durable tenant-scoped work queue record.

Jobs are data, not authority. Workers must re-authorize every action through
Tinlance Agent Platform; payloads must not contain credentials or secrets.
"""
from sqlalchemy import (
    CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, JSON,
    String, Text, UniqueConstraint, func,
)
from core.database import Base


class DurableJob(Base):
    __tablename__ = "durable_jobs"
    __table_args__ = (
        UniqueConstraint("org_id", "idempotency_key", name="uq_durable_jobs_org_idempotency"),
        CheckConstraint("attempts >= 0", name="ck_durable_jobs_attempts_nonnegative"),
        CheckConstraint("max_attempts >= 1", name="ck_durable_jobs_max_attempts_positive"),
        CheckConstraint(
            "status IN ('pending','running','retry_wait','succeeded','failed','dead_letter','cancelled')",
            name="ck_durable_jobs_status",
        ),
        Index("ix_durable_jobs_claim", "status", "available_at", "created_at"),
        Index("ix_durable_jobs_org_created", "org_id", "created_at"),
    )

    id = Column(String(64), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    job_type = Column(String(160), nullable=False)
    schema_version = Column(String(32), nullable=False, default="1")
    idempotency_key = Column(String(255), nullable=False)
    payload = Column(JSON, nullable=False, default=dict)
    status = Column(String(32), nullable=False, default="pending", server_default="pending")
    attempts = Column(Integer, nullable=False, default=0, server_default="0")
    max_attempts = Column(Integer, nullable=False, default=5, server_default="5")
    available_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    lease_owner = Column(String(255), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    cancellation_requested_at = Column(DateTime(timezone=True), nullable=True)
    last_error_code = Column(String(100), nullable=True)
    result_metadata = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<DurableJob {self.id} org={self.org_id} type={self.job_type} status={self.status}>"


class OutboxEvent(Base):
    """Transactional outbox row; publication is at-least-once and consumers dedupe by id."""
    __tablename__ = "outbox_events"
    __table_args__ = (
        UniqueConstraint("org_id", "idempotency_key", name="uq_outbox_org_idempotency"),
        CheckConstraint(
            "status IN ('pending','publishing','published','dead_letter')",
            name="ck_outbox_events_status",
        ),
        Index("ix_outbox_events_claim", "status", "available_at", "created_at"),
        Index("ix_outbox_events_org_created", "org_id", "created_at"),
    )

    id = Column(String(64), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    aggregate_type = Column(String(100), nullable=False)
    aggregate_id = Column(String(255), nullable=False)
    event_type = Column(String(160), nullable=False)
    schema_version = Column(String(32), nullable=False, default="1")
    idempotency_key = Column(String(255), nullable=False)
    payload = Column(JSON, nullable=False, default=dict)
    status = Column(String(32), nullable=False, default="pending", server_default="pending")
    attempts = Column(Integer, nullable=False, default=0, server_default="0")
    available_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    lease_owner = Column(String(255), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    last_error_code = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    published_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<OutboxEvent {self.id} org={self.org_id} type={self.event_type} status={self.status}>"
