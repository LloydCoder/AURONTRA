"""Durable, provenance-bearing endpoint telemetry and tenant RLS."""
from alembic import op
import sqlalchemy as sa

revision = "0007_telemetry_evidence"
down_revision = "0006_remediation_intents"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "telemetry_records" not in tables:
        op.create_table(
            "telemetry_records",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("device_id", sa.String(128), nullable=False),
            sa.Column("event_id", sa.String(36), nullable=False),
            sa.Column("schema_version", sa.String(16), nullable=False, server_default="1"),
            sa.Column("source", sa.String(32), nullable=False, server_default="endpoint_agent"),
            sa.Column("agent_version", sa.String(64), nullable=True),
            sa.Column("key_thumbprint", sa.String(128), nullable=False),
            sa.Column("proof_jti", sa.String(256), nullable=False, unique=True),
            sa.Column("request_id", sa.String(128), nullable=False),
            sa.Column("request_hash", sa.String(64), nullable=False),
            sa.Column("payload_hash", sa.String(64), nullable=False),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("metrics", sa.JSON(), nullable=False),
            sa.Column("missing_metrics", sa.JSON(), nullable=False),
            sa.Column("quality_flags", sa.JSON(), nullable=False),
            sa.Column("computed_score", sa.Integer(), nullable=True),
            sa.Column("score_components", sa.JSON(), nullable=False),
            sa.Column("score_status", sa.String(32), nullable=True),
            sa.Column("retention_expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(
                ["org_id", "device_id"], ["devices.org_id", "devices.id"],
                name="fk_telemetry_records_org_device", ondelete="RESTRICT",
            ),
            sa.UniqueConstraint("org_id", "device_id", "event_id", name="uq_telemetry_org_device_event"),
            sa.CheckConstraint("schema_version = '1'", name="ck_telemetry_schema_version"),
            sa.CheckConstraint(
                "computed_score IS NULL OR (computed_score >= 0 AND computed_score <= 100)",
                name="ck_telemetry_computed_score_range",
            ),
        )
        op.create_index(
            "ix_telemetry_org_device_observed", "telemetry_records",
            ["org_id", "device_id", "observed_at"],
        )
        op.create_index(
            "ix_telemetry_org_retention", "telemetry_records",
            ["org_id", "retention_expires_at"],
        )
        op.create_index(
            "ix_telemetry_records_retention_expires_at", "telemetry_records",
            ["retention_expires_at"],
        )

    if bind.dialect.name == "postgresql":
        op.execute(sa.text('ALTER TABLE "telemetry_records" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "telemetry_records" FORCE ROW LEVEL SECURITY'))
        existing = bind.execute(sa.text(
            "SELECT 1 FROM pg_policies WHERE schemaname = current_schema() "
            "AND tablename = 'telemetry_records' AND policyname = 'tenant_isolation_telemetry_records'"
        )).first()
        if not existing:
            op.execute(sa.text(
                'CREATE POLICY "tenant_isolation_telemetry_records" ON "telemetry_records" '
                'USING ("org_id"::text = current_setting(\'app.current_org_id\', true)) '
                'WITH CHECK ("org_id"::text = current_setting(\'app.current_org_id\', true))'
            ))


def downgrade():
    raise RuntimeError(
        "Telemetry is provenance evidence; rollback requires a reviewed backup-and-restore procedure."
    )
