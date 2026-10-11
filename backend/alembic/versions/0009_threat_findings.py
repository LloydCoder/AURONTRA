"""Phase 15: durable tenant-scoped threat findings and evidence provenance."""
from alembic import op
import sqlalchemy as sa

revision = "0009_threat_findings"
down_revision = "0008_ticket_ai_knowledge"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if "threat_findings" not in set(sa.inspect(bind).get_table_names()):
        op.create_table(
            "threat_findings",
            sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
            sa.Column("org_id", sa.String(length=64), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
            sa.Column("source_event_id", sa.String(length=128), nullable=True),
            sa.Column("src_ip", sa.String(length=45), nullable=True),
            sa.Column("protocol", sa.String(length=16), nullable=True),
            sa.Column("dst_port", sa.Integer(), nullable=True),
            sa.Column("threat_level", sa.String(length=16), nullable=False),
            sa.Column("score", sa.Integer(), nullable=False),
            sa.Column("score_components", sa.JSON(), nullable=False),
            sa.Column("mitre_ttp", sa.String(length=32), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("detector_version", sa.String(length=64), nullable=False, server_default="heuristic-threat-score.v2"),
            sa.Column("ruleset_version", sa.String(length=64), nullable=False, server_default="threat-rules.v1"),
            sa.Column("score_semantics", sa.String(length=64), nullable=False, server_default="heuristic_0_to_100_not_probability"),
            sa.Column("evidence_sha256", sa.String(length=64), nullable=False),
            sa.Column("evidence", sa.JSON(), nullable=False),
            sa.Column("containment_recommended", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("containment_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="assessed"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.CheckConstraint("score >= 0 AND score <= 100", name="ck_threat_finding_score_range"),
            sa.CheckConstraint("threat_level IN ('info', 'low', 'medium', 'high', 'critical')", name="ck_threat_finding_threat_level"),
            sa.CheckConstraint("status IN ('assessed', 'review_required')", name="ck_threat_finding_status"),
            sa.CheckConstraint("containment_verified = false", name="ck_threat_finding_no_unverified_containment"),
            sa.CheckConstraint("length(evidence_sha256) = 64", name="ck_threat_finding_evidence_hash_length"),
            sa.UniqueConstraint("org_id", "source_event_id", name="uq_threat_finding_org_source_event"),
        )
        op.create_index("ix_threat_findings_org_created", "threat_findings", ["org_id", "created_at"])
        op.create_index("ix_threat_findings_org_id", "threat_findings", ["org_id"])

    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE threat_findings ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE threat_findings FORCE ROW LEVEL SECURITY")
        op.execute(
            "CREATE POLICY threat_findings_select ON threat_findings FOR SELECT USING "
            "(NULLIF(current_setting('app.current_org_id', true), '') IS NOT NULL "
            "AND org_id = NULLIF(current_setting('app.current_org_id', true), ''))"
        )
        op.execute(
            "CREATE POLICY threat_findings_insert ON threat_findings FOR INSERT WITH CHECK "
            "(NULLIF(current_setting('app.current_org_id', true), '') IS NOT NULL "
            "AND org_id = NULLIF(current_setting('app.current_org_id', true), '') "
            "AND containment_verified = false "
            "AND status IN ('assessed', 'review_required'))"
        )
        # Intentionally no UPDATE or DELETE policies: findings are immutable to the tenant app role.


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and "threat_findings" in set(sa.inspect(bind).get_table_names()):
        op.execute("DROP POLICY IF EXISTS threat_findings_insert ON threat_findings")
        op.execute("DROP POLICY IF EXISTS threat_findings_select ON threat_findings")
        op.execute("ALTER TABLE threat_findings NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE threat_findings DISABLE ROW LEVEL SECURITY")
    if "threat_findings" in set(sa.inspect(bind).get_table_names()):
        op.drop_table("threat_findings")
