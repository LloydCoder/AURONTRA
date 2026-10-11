"""Tenant-scoped immutable report artifacts with PostgreSQL RLS."""
from alembic import op
import sqlalchemy as sa

revision = "0014_report_artifacts"
down_revision = "0013_containment_awaiting_verification"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "report_artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("report_type", sa.String(32), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("input_provenance", sa.JSON(), nullable=False),
        sa.Column("report_payload", sa.JSON(), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("report_type IN ('roi','compliance','executive_summary')", name="ck_report_artifacts_type"),
        sa.UniqueConstraint("org_id", "id", name="uq_report_artifacts_org_id"),
    )
    op.create_index("ix_report_artifacts_org_created", "report_artifacts", ["org_id", "created_at"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text('ALTER TABLE "report_artifacts" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "report_artifacts" FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text(
            'CREATE POLICY "tenant_isolation_report_artifacts" ON "report_artifacts" '
            'USING ("org_id"::text = current_setting(\'app.current_org_id\', true)) '
            'WITH CHECK ("org_id"::text = current_setting(\'app.current_org_id\', true))'
        ))
        op.execute(sa.text("""
            CREATE FUNCTION reject_report_artifact_mutation() RETURNS trigger AS $
            BEGIN
                RAISE EXCEPTION 'report artifacts are append-only';
            END;
            $ LANGUAGE plpgsql
        """))
        op.execute(sa.text("""
            CREATE TRIGGER report_artifacts_no_update
            BEFORE UPDATE OR DELETE ON report_artifacts
            FOR EACH ROW EXECUTE FUNCTION reject_report_artifact_mutation()
        """))
    else:
        op.execute(sa.text("""
            CREATE TRIGGER report_artifacts_no_update
            BEFORE UPDATE ON report_artifacts
            BEGIN SELECT RAISE(ABORT, 'report artifacts are append-only'); END
        """))
        op.execute(sa.text("""
            CREATE TRIGGER report_artifacts_no_delete
            BEFORE DELETE ON report_artifacts
            BEGIN SELECT RAISE(ABORT, 'report artifacts are append-only'); END
        """))


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT COUNT(*) FROM report_artifacts")).scalar_one():
        raise RuntimeError("Cannot drop report artifacts with persisted evidence; use a reviewed archive procedure.")
    if bind.dialect.name == "postgresql":
        op.execute(sa.text('DROP TRIGGER IF EXISTS report_artifacts_no_update ON report_artifacts'))
        op.execute(sa.text("DROP FUNCTION IF EXISTS reject_report_artifact_mutation()"))
        op.execute(sa.text('DROP POLICY IF EXISTS "tenant_isolation_report_artifacts" ON report_artifacts'))
    else:
        op.execute(sa.text("DROP TRIGGER IF EXISTS report_artifacts_no_update"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS report_artifacts_no_delete"))
    op.drop_index("ix_report_artifacts_org_created", table_name="report_artifacts")
    op.drop_table("report_artifacts")
