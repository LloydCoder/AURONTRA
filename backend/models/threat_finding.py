"""Durable, tenant-scoped threat assessment evidence.

Rows represent an assessment, never proof of successful containment. Evidence is
append-only for the tenant application role; verified enforcement is a separate
future capability and cannot be asserted by this schema revision.
"""
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from core.database import Base


class ThreatFinding(Base):
    __tablename__ = "threat_findings"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 100", name="ck_threat_finding_score_range"),
        CheckConstraint(
            "threat_level IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_threat_finding_threat_level",
        ),
        CheckConstraint(
            "status IN ('assessed', 'review_required')",
            name="ck_threat_finding_status",
        ),
        CheckConstraint(
            "containment_verified = false",
            name="ck_threat_finding_no_unverified_containment",
        ),
        CheckConstraint(
            "length(evidence_sha256) = 64",
            name="ck_threat_finding_evidence_hash_length",
        ),
        UniqueConstraint("org_id", "source_event_id", name="uq_threat_finding_org_source_event"),
        Index("ix_threat_findings_org_created", "org_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    source_event_id = Column(String(128), nullable=True)
    src_ip = Column(String(45), nullable=True)
    protocol = Column(String(16), nullable=True)
    dst_port = Column(Integer, nullable=True)
    threat_level = Column(String(16), nullable=False)
    score = Column(Integer, nullable=False)
    score_components = Column(JSON, nullable=False)
    mitre_ttp = Column(String(32), nullable=False)
    reason = Column(Text, nullable=False)
    detector_version = Column(String(64), nullable=False, default="heuristic-threat-score.v2", server_default="heuristic-threat-score.v2")
    ruleset_version = Column(String(64), nullable=False, default="threat-rules.v1", server_default="threat-rules.v1")
    score_semantics = Column(String(64), nullable=False, default="heuristic_0_to_100_not_probability", server_default="heuristic_0_to_100_not_probability")
    evidence_sha256 = Column(String(64), nullable=False)
    evidence = Column(JSON, nullable=False)
    containment_recommended = Column(Boolean, nullable=False, default=False, server_default="false")
    containment_verified = Column(Boolean, nullable=False, default=False, server_default="false")
    status = Column(String(32), nullable=False, default="assessed", server_default="assessed")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
