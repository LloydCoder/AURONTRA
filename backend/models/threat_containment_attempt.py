"""Durable, tenant-scoped attempts to contain a threat finding through the Agent Platform."""
from sqlalchemy import (
    CheckConstraint, Column, DateTime, ForeignKey, ForeignKeyConstraint,
    Index, Integer, JSON, String, UniqueConstraint, func,
)
from core.database import Base


class ThreatContainmentAttempt(Base):
    __tablename__ = "threat_containment_attempts"
    __table_args__ = (
        UniqueConstraint("org_id", "finding_id", name="uq_threat_containment_org_finding"),
        UniqueConstraint("org_id", "id", name="uq_threat_containment_org_id"),
        UniqueConstraint("org_id", "idempotency_key", name="uq_threat_containment_org_idempotency"),
        ForeignKeyConstraint(
            ["org_id", "finding_id"],
            ["threat_findings.org_id", "threat_findings.id"],
            name="fk_threat_containment_org_finding",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["org_id", "device_id"],
            ["devices.org_id", "devices.id"],
            name="fk_threat_containment_org_device",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "status IN ('submitting','approval_pending','platform_pending','unknown_outcome',"
            "'contained','failed','verification_failed','cancelled')",
            name="ck_threat_containment_status",
        ),
        CheckConstraint("version >= 0", name="ck_threat_containment_version_nonnegative"),
        Index("ix_threat_containment_org_status_updated", "org_id", "status", "updated_at"),
    )

    id = Column(String(36), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    finding_id = Column(String(36), nullable=False)
    device_id = Column(String(128), nullable=False)
    idempotency_key = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False, default="submitting", server_default="submitting")
    version = Column(Integer, nullable=False, default=0, server_default="0")
    platform_action_id = Column(String(36), nullable=False)
    platform_run_id = Column(String(36), nullable=True)
    platform_execution_id = Column(String(36), nullable=True)
    platform_state = Column(String(64), nullable=True)
    platform_evidence_ids = Column(JSON, nullable=False, default=list)
    audit_event_ids = Column(JSON, nullable=False, default=list)
    verification_evidence_ids = Column(JSON, nullable=False, default=list)
    reason_code = Column(String(100), nullable=True)
    last_error_code = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<ThreatContainmentAttempt {self.id} org={self.org_id} status={self.status}>"
