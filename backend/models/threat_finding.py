"""Durable tenant-scoped threat assessment evidence (not proof of containment)."""
from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, JSON,
    String, UniqueConstraint, func,
)
from core.database import Base


class ThreatFinding(Base):
    __tablename__ = "threat_findings"
    __table_args__ = (
        UniqueConstraint("org_id", "event_id", name="uq_threat_findings_org_event"),
        CheckConstraint("score >= 0 AND score <= 100", name="ck_threat_findings_score_range"),
        CheckConstraint(
            "threat_level IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_threat_findings_level",
        ),
        CheckConstraint(
            "decision_status IN ('assessed', 'analysis_unavailable')",
            name="ck_threat_findings_decision_status",
        ),
        CheckConstraint("length(signal_sha256) = 64", name="ck_threat_findings_signal_hash_length"),
        Index("ix_threat_findings_org_observed", "org_id", "observed_at"),
        Index("ix_threat_findings_org_level", "org_id", "threat_level", "received_at"),
    )

    id = Column(String(36), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    event_id = Column(String(128), nullable=False)
    source = Column(String(32), nullable=False, default="api_signal", server_default="api_signal")
    detector_version = Column(String(64), nullable=False)
    observed_at = Column(DateTime(timezone=True), nullable=False)
    received_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    signal_sha256 = Column(String(64), nullable=False)
    signal = Column(JSON, nullable=False)
    assessment = Column(JSON, nullable=False)
    score = Column(Integer, nullable=False)
    threat_level = Column(String(16), nullable=False)
    mitre_ttp = Column(String(32), nullable=False)
    decision_status = Column(String(32), nullable=False, default="assessed", server_default="assessed")
    containment_verified = Column(Boolean, nullable=False, default=False, server_default="false")

    def __repr__(self) -> str:
        return f"<ThreatFinding {self.id} org={self.org_id} level={self.threat_level}>"
