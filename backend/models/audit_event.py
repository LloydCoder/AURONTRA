"""Durable, tenant-scoped audit evidence. Records are append-only at the ORM layer."""
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON, Index, UniqueConstraint, event, func
from core.database import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_org_created", "org_id", "created_at"),
        Index("ix_audit_events_org_sequence", "org_id", "sequence"),
        UniqueConstraint("org_id", "sequence", name="uq_audit_events_org_sequence"),
    )

    id = Column(String(64), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    sequence = Column(Integer, nullable=False)
    actor_subject = Column(String(255), nullable=False)
    event_type = Column(String(160), nullable=False)
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(255), nullable=False)
    request_id = Column(String(128), nullable=True, index=True)
    event_data = Column(JSON, nullable=False, default=dict)
    previous_hash = Column(String(64), nullable=False)
    event_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    def __repr__(self) -> str:
        return f"<AuditEvent {self.id} org={self.org_id} type={self.event_type}>"


@event.listens_for(AuditEvent, "before_update")
def _prevent_audit_update(mapper, connection, target):
    raise ValueError("Audit events are append-only and cannot be updated")


@event.listens_for(AuditEvent, "before_delete")
def _prevent_audit_delete(mapper, connection, target):
    raise ValueError("Audit events are append-only and cannot be deleted through the ORM")
