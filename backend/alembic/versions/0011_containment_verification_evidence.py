"""Independent signed containment verification evidence and pending state."""
from alembic import op
import sqlalchemy as sa

revision = "0011_containment_verification_evidence"
down_revision = "0010_threat_containment"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "threat_containment_attempts" not in tables:
        raise RuntimeError("0010_threat_containment must be applied before this migration.")

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("threat_containment_attempts") as batch:
            batch.drop_constraint("ck_threat_containment_status", type_="check")
            batch.create_check_constraint(
                "ck_threat_containment_status",
                "status IN ('submitting','approval_pending','platform_pending','unknown_outcome',"
                "'awaiting_verification','contained','failed','verification_failed','cancelled')",
            )
            batch.create_unique_constraint("uq_threat_containment_org_id", ["org_id", "id"])
    else:
        op.drop_constraint("ck_threat_containment_status", "threat_containment_attempts", type_="check")
        op.create_check_constraint(
            "ck_threat_containment_status",
            "threat_containment_attempts",
            "status IN ('submitting','approval_pending','platform_pending','unknown_outcome',"
            "'awaiting_verification','contained','failed','verification_failed','cancelled')",
        )
        unique_names = {item["name"] for item in sa.inspect(bind).get_unique_constraints("threat_containment_attempts")}
        if "uq_threat_containment_org_id" not in unique_names:
            op.create_unique_constraint("uq_threat_containment_org_id", "threat_containment_attempts", ["org_id", "id"])

    if "containment_verification_evidence" not in tables:
        op.create_table(
            "containment_verification_evidence",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("attempt_id", sa.String(36), nullable=False),
            sa.Column("finding_id", sa.String(36), nullable=False),
            sa.Column("device_id", sa.String(128), nullable=False),
            sa.Column("action_id", sa.String(36), nullable=False),
            sa.Column("execution_id", sa.String(36), nullable=False),
            sa.Column("source_id", sa.String(128), nullable=False),
            sa.Column("key_id", sa.String(128), nullable=False),
            sa.Column("source_type", sa.String(32), nullable=False),
            sa.Column("nonce", sa.String(128), nullable=False),
            sa.Column("evidence_id", sa.String(128), nullable=False),
            sa.Column("payload_sha256", sa.String(64), nullable=False),
            sa.Column("signature_valid", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("isolation_active", sa.Boolean(), nullable=False),
            sa.Column("reason_code", sa.String(80), nullable=False),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("org_id", "id", name="uq_containment_verification_org_id"),
            sa.UniqueConstraint("org_id", "source_id", "nonce", name="uq_containment_verification_source_nonce"),
            sa.UniqueConstraint("org_id", "source_id", "evidence_id", name="uq_containment_verification_source_evidence"),
            sa.ForeignKeyConstraint(
                ["org_id", "attempt_id"], ["threat_containment_attempts.org_id", "threat_containment_attempts.id"],
                name="fk_containment_verification_org_attempt", ondelete="RESTRICT",
            ),
            sa.ForeignKeyConstraint(
                ["org_id", "finding_id"], ["threat_findings.org_id", "threat_findings.id"],
                name="fk_containment_verification_org_finding", ondelete="RESTRICT",
            ),
            sa.ForeignKeyConstraint(
                ["org_id", "device_id"], ["devices.org_id", "devices.id"],
                name="fk_containment_verification_org_device", ondelete="RESTRICT",
            ),
            sa.CheckConstraint(
                "source_type IN ('network_control_plane','cloud_control_plane')",
                name="ck_containment_verification_source_type",
            ),
            sa.CheckConstraint("length(payload_sha256) = 64", name="ck_containment_verification_payload_hash"),
        )
        op.create_index(
            "ix_containment_verification_lookup", "containment_verification_evidence",
            ["org_id", "attempt_id", "execution_id", "observed_at"],
        )

    if bind.dialect.name == "postgresql":
        op.execute(sa.text('ALTER TABLE "containment_verification_evidence" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "containment_verification_evidence" FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text(
            'CREATE POLICY "tenant_isolation_containment_verification" ON "containment_verification_evidence" '
            'USING ("org_id"::text = current_setting(\'app.current_org_id\', true)) '
            'WITH CHECK ("org_id"::text = current_setting(\'app.current_org_id\', true))'
        ))


def downgrade():
    raise RuntimeError("Containment verification evidence is forensic evidence; rollback requires a reviewed backup-and-restore procedure.")
