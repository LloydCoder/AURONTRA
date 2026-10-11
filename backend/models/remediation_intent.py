"""Durable tenant-scoped remediation intent and reconciliation state."""
from sqlalchemy import (
    CheckConstraint, Column, DateTime, ForeignKey, ForeignKeyConstraint,
    Index, Integer, JSON, String, UniqueConstraint, func,
)
from core.database import Base


class RemediationIntent(Base):
    __tablename__ = "remediation_intents"
    __table_args__ = (
        UniqueConstraint("org_id", "idempotency_key", name="uq_remediation_intents_org_idempotency"),
        UniqueConstraint("org_id", "plan_id", name="uq_remediation_intents_org_plan"),
        ForeignKeyConstraint(
            ["org_id", "device_id"],
            ["devices.org_id", "devices.id"],
            name="fk_remediation_intents_org_device",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "status IN ('proposed','queued','submitting','approval_pending','platform_pending',"
            "'awaiting_verification','unknown_outcome','verified','failed','verification_failed','cancelled')",
            name="ck_remediation_intents_status",
        ),
        CheckConstraint("version >= 0", name="ck_remediation_intents_version_nonnegative"),
        Index("ix_remediation_intents_reconcile", "org_id", "status", "updated_at"),
        Index("ix_remediation_intents_device_created", "org_id", "device_id", "created_at"),
    )

    id = Column(String(36), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    device_id = Column(String(128), nullable=False)
    plan_id = Column(String(36), nullable=False)
    idempotency_key = Column(String(255), nullable=False)
    playbook = Column(String(64), nullable=False)
    source_evidence_id = Column(String(128), nullable=False)
    plan_payload = Column(JSON, nullable=False)
    status = Column(String(32), nullable=False, default="proposed", server_default="proposed")
    version = Column(Integer, nullable=False, default=0, server_default="0")
    platform_state = Column(String(64), nullable=True)
    platform_run_id = Column(String(64), nullable=True)
    platform_execution_id = Column(String(64), nullable=True)
    platform_evidence_ids = Column(JSON, nullable=False, default=list)
    audit_event_ids = Column(JSON, nullable=False, default=list)
    postcondition_evidence_ids = Column(JSON, nullable=False, default=list)
    result_metadata = Column(JSON, nullable=False, default=dict)
    reason_code = Column(String(100), nullable=True)
    last_error_code = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<RemediationIntent {self.id} org={self.org_id} status={self.status} version={self.version}>"
