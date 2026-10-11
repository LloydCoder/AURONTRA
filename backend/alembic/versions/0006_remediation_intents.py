"""Durable remediation intents, idempotent jobs, and tenant-isolated state."""
from alembic import op
import sqlalchemy as sa

revision = "0006_remediation_intents"
down_revision = "0005_agent_dpop_identity"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "remediation_intents" not in tables:
        op.create_table(
            "remediation_intents",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("device_id", sa.String(128), nullable=False),
            sa.Column("plan_id", sa.String(36), nullable=False),
            sa.Column("idempotency_key", sa.String(255), nullable=False),
            sa.Column("playbook", sa.String(64), nullable=False),
            sa.Column("source_evidence_id", sa.String(128), nullable=False),
            sa.Column("plan_payload", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(32), nullable=False, server_default="proposed"),
            sa.Column("version", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("platform_state", sa.String(64), nullable=True),
            sa.Column("platform_run_id", sa.String(64), nullable=True),
            sa.Column("platform_execution_id", sa.String(64), nullable=True),
            sa.Column("platform_evidence_ids", sa.JSON(), nullable=False),
            sa.Column("audit_event_ids", sa.JSON(), nullable=False),
            sa.Column("postcondition_evidence_ids", sa.JSON(), nullable=False),
            sa.Column("result_metadata", sa.JSON(), nullable=False),
            sa.Column("last_error_code", sa.String(100), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(
                ["org_id", "device_id"], ["devices.org_id", "devices.id"],
                name="fk_remediation_intents_org_device", ondelete="RESTRICT",
            ),
            sa.UniqueConstraint("org_id", "idempotency_key", name="uq_remediation_intents_org_idempotency"),
            sa.UniqueConstraint("org_id", "plan_id", name="uq_remediation_intents_org_plan"),
            sa.CheckConstraint(
                "status IN ('proposed','queued','submitting','approval_pending','platform_pending',"
                "'awaiting_verification','unknown_outcome','verified','failed','verification_failed','cancelled')",
                name="ck_remediation_intents_status",
            ),
            sa.CheckConstraint("version >= 0", name="ck_remediation_intents_version_nonnegative"),
        )
        op.create_index(
            "ix_remediation_intents_reconcile", "remediation_intents",
            ["org_id", "status", "updated_at"],
        )
        op.create_index(
            "ix_remediation_intents_device_created", "remediation_intents",
            ["org_id", "device_id", "created_at"],
        )

    if bind.dialect.name == "postgresql":
        op.execute(sa.text('ALTER TABLE "remediation_intents" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "remediation_intents" FORCE ROW LEVEL SECURITY'))
        existing = bind.execute(sa.text(
            "SELECT 1 FROM pg_policies WHERE schemaname = current_schema() "
            "AND tablename = 'remediation_intents' AND policyname = 'tenant_isolation_remediation_intents'"
        )).first()
        if not existing:
            op.execute(sa.text(
                'CREATE POLICY "tenant_isolation_remediation_intents" ON "remediation_intents" '
                'USING ("org_id"::text = current_setting(\'app.current_org_id\', true)) '
                'WITH CHECK ("org_id"::text = current_setting(\'app.current_org_id\', true))'
            ))


def downgrade():
    raise RuntimeError(
        "Remediation intents are operational evidence; rollback requires a reviewed backup-and-restore procedure."
    )
