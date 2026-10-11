"""Append-only tenant-scoped report artifacts with content integrity digests."""
from sqlalchemy import (
    CheckConstraint, Column, DateTime, ForeignKey, Index, JSON, String,
    UniqueConstraint, event, func,
)
from core.database import Base


class ReportArtifact(Base):
    __tablename__ = "report_artifacts"
    __table_args__ = (
        CheckConstraint("report_type IN ('roi','compliance','executive_summary')", name="ck_report_artifacts_type"),
        Index("ix_report_artifacts_org_created", "org_id", "created_at"),
        UniqueConstraint("org_id", "id", name="uq_report_artifacts_org_id"),
    )

    id = Column(String(36), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    report_type = Column(String(32), nullable=False)
    period_start = Column(DateTime(timezone=True), nullable=False)
    period_end = Column(DateTime(timezone=True), nullable=False)
    created_by = Column(String(255), nullable=False)
    input_provenance = Column(JSON, nullable=False)
    report_payload = Column(JSON, nullable=False)
    payload_sha256 = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    def __repr__(self) -> str:
        return f"<ReportArtifact {self.id} org={self.org_id} type={self.report_type}>"


@event.listens_for(ReportArtifact, "before_update")
def _prevent_report_update(mapper, connection, target):
    raise ValueError("Report artifacts are append-only and cannot be updated")


@event.listens_for(ReportArtifact, "before_delete")
def _prevent_report_delete(mapper, connection, target):
    raise ValueError("Report artifacts are append-only and cannot be deleted through the ORM")
