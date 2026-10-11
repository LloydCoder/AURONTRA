"""Signed evidence from an independent network/cloud control plane after isolation."""
from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, ForeignKey, ForeignKeyConstraint,
    Index, String, UniqueConstraint, func,
)
from core.database import Base


class ContainmentVerificationEvidence(Base):
    __tablename__ = "containment_verification_evidence"
    __table_args__ = (
        UniqueConstraint("org_id", "id", name="uq_containment_verification_org_id"),
        UniqueConstraint("org_id", "source_id", "nonce", name="uq_containment_verification_source_nonce"),
        UniqueConstraint("org_id", "source_id", "evidence_id", name="uq_containment_verification_source_evidence"),
        ForeignKeyConstraint(
            ["org_id", "attempt_id"],
            ["threat_containment_attempts.org_id", "threat_containment_attempts.id"],
            name="fk_containment_verification_org_attempt",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["org_id", "finding_id"],
            ["threat_findings.org_id", "threat_findings.id"],
            name="fk_containment_verification_org_finding",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["org_id", "device_id"],
            ["devices.org_id", "devices.id"],
            name="fk_containment_verification_org_device",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "source_type IN ('network_control_plane','cloud_control_plane')",
            name="ck_containment_verification_source_type",
        ),
        CheckConstraint("length(payload_sha256) = 64", name="ck_containment_verification_payload_hash"),
        Index("ix_containment_verification_lookup", "org_id", "attempt_id", "execution_id", "observed_at"),
    )

    id = Column(String(36), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    attempt_id = Column(String(36), nullable=False)
    finding_id = Column(String(36), nullable=False)
    device_id = Column(String(128), nullable=False)
    action_id = Column(String(36), nullable=False)
    execution_id = Column(String(36), nullable=False)
    source_id = Column(String(128), nullable=False)
    key_id = Column(String(128), nullable=False)
    source_type = Column(String(32), nullable=False)
    nonce = Column(String(128), nullable=False)
    evidence_id = Column(String(128), nullable=False)
    payload_sha256 = Column(String(64), nullable=False)
    signature_valid = Column(Boolean, nullable=False, default=False, server_default="false")
    isolation_active = Column(Boolean, nullable=False)
    reason_code = Column(String(80), nullable=False)
    observed_at = Column(DateTime(timezone=True), nullable=False)
    received_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    def __repr__(self) -> str:
        return f"<ContainmentVerificationEvidence {self.id} org={self.org_id} source={self.source_id}>"
