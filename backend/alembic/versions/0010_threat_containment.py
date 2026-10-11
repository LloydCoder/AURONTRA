"""Verified threat containment attempt ledger."""
from alembic import op
import sqlalchemy as sa

revision = "0010_threat_containment"
down_revision = "0009_threat_findings"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "threat_findings" not in tables:
        raise RuntimeError("0009_threat_findings must be applied before this migration.")

    columns = {column["name"] for column in sa.inspect(bind).get_columns("threat_findings")}
    if "device_id" not in columns:
        with op.batch_alter_table("threat_findings") as batch:
            batch.add_column(sa.Column("device_id", sa.String(128), nullable=True))
            batch.create_unique_constraint("uq_threat_findings_org_id_id", ["org_id", "id"])
            batch.create_foreign_key(
                "fk_threat_findings_org_device",
                "devices",
                ["org_id", "device_id"],
                ["org_id", "id"],
                ondelete="RESTRICT",
            )

    if "threat_containment_attempts" not in tables:
        op.create_table(
            "threat_containment_attempts",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("finding_id", sa.String(36), nullable=False),
            sa.Column("device_id", sa.String(128), nullable=False),
            sa.Column("idempotency_key", sa.String(128), nullable=False),
            sa.Column("status", sa.String(32), nullable=False, server_default="submitting"),
            sa.Column("version", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("platform_action_id", sa.String(36), nullable=False),
            sa.Column("platform_run_id", sa.String(36), nullable=True),
            sa.Column("platform_execution_id", sa.String(36), nullable=True),
            sa.Column("platform_state", sa.String(64), nullable=True),
            sa.Column("platform_evidence_ids", sa.JSON(), nullable=False),
            sa.Column("audit_event_ids", sa.JSON(), nullable=False),
            sa.Column("verification_evidence_ids", sa.JSON(), nullable=False),
            sa.Column("reason_code", sa.String(100), nullable=True),
            sa.Column("last_error_code", sa.String(100), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("org_id", "finding_id", name="uq_threat_containment_org_finding"),
            sa.UniqueConstraint("org_id", "idempotency_key", name="uq_threat_containment_org_idempotency"),
            sa.ForeignKeyConstraint(
                ["org_id", "finding_id"], ["threat_findings.org_id", "threat_findings.id"],
                name="fk_threat_containment_org_finding", ondelete="RESTRICT",
            ),
            sa.ForeignKeyConstraint(
                ["org_id", "device_id"], ["devices.org_id", "devices.id"],
                name="fk_threat_containment_org_device", ondelete="RESTRICT",
            ),
            sa.CheckConstraint(
                "status IN ('submitting','approval_pending','platform_pending','unknown_outcome','contained','failed','verification_failed','cancelled')",
                name="ck_threat_containment_status",
            ),
            sa.CheckConstraint("version >= 0", name="ck_threat_containment_version_nonnegative"),
        )
        op.create_index(
            "ix_threat_containment_org_status_updated", "threat_containment_attempts",
            ["org_id", "status", "updated_at"],
        )

    if bind.dialect.name == "postgresql":
        for table in ("threat_findings", "threat_containment_attempts"):
            op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
            op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
            policy = "tenant_isolation_threat_containment" if table == "threat_containment_attempts" else "tenant_isolation_threat_findings"
            # The Phase 15 policy already exists for threat_findings; only add the new policy here.
            if table == "threat_containment_attempts":
                op.execute(sa.text(
                    'CREATE POLICY "tenant_isolation_threat_containment" ON "threat_containment_attempts" '
                    'USING ("org_id"::text = current_setting(\'app.current_org_id\', true)) '
                    'WITH CHECK ("org_id"::text = current_setting(\'app.current_org_id\', true))'
                ))


def downgrade():
    raise RuntimeError("Threat containment history is forensic evidence; rollback requires a reviewed backup-and-restore procedure.")
