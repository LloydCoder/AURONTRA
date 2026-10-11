"""Tenant-scoped threat assessment evidence and RLS."""
from alembic import op
import sqlalchemy as sa

revision = "0009_threat_findings"
down_revision = "0008_ticket_ai_knowledge"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "threat_findings" not in tables:
        op.create_table(
            "threat_findings",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("event_id", sa.String(128), nullable=False),
            sa.Column("source", sa.String(32), nullable=False, server_default="api_signal"),
            sa.Column("detector_version", sa.String(64), nullable=False),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("signal_sha256", sa.String(64), nullable=False),
            sa.Column("signal", sa.JSON(), nullable=False),
            sa.Column("assessment", sa.JSON(), nullable=False),
            sa.Column("score", sa.Integer(), nullable=False),
            sa.Column("threat_level", sa.String(16), nullable=False),
            sa.Column("mitre_ttp", sa.String(32), nullable=False),
            sa.Column("decision_status", sa.String(32), nullable=False, server_default="assessed"),
            sa.Column("containment_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.UniqueConstraint("org_id", "event_id", name="uq_threat_findings_org_event"),
            sa.CheckConstraint("score >= 0 AND score <= 100", name="ck_threat_findings_score_range"),
            sa.CheckConstraint("threat_level IN ('info', 'low', 'medium', 'high', 'critical')", name="ck_threat_findings_level"),
            sa.CheckConstraint("decision_status IN ('assessed', 'analysis_unavailable')", name="ck_threat_findings_decision_status"),
            sa.CheckConstraint("length(signal_sha256) = 64", name="ck_threat_findings_signal_hash_length"),
        )
        op.create_index("ix_threat_findings_org_observed", "threat_findings", ["org_id", "observed_at"])
        op.create_index("ix_threat_findings_org_level", "threat_findings", ["org_id", "threat_level", "received_at"])
    if bind.dialect.name == "postgresql":
        op.execute(sa.text('ALTER TABLE "threat_findings" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "threat_findings" FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text(
            'CREATE POLICY "tenant_isolation_threat_findings" ON "threat_findings" '
            'USING ("org_id"::text = current_setting(\'app.current_org_id\', true)) '
            'WITH CHECK ("org_id"::text = current_setting(\'app.current_org_id\', true))'
        ))


def downgrade():
    raise RuntimeError("Threat findings are forensic evidence; rollback requires a reviewed backup-and-restore procedure.")
