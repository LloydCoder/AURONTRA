"""Durable job queue and transactional outbox tables.

Existing business records are untouched. Tenant-owned queue rows receive forced
PostgreSQL RLS. Outbox delivery is at-least-once; consumers must deduplicate.
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_durable_jobs_and_outbox"
down_revision = "0002_tenant_foreign_keys_and_rls"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())

    if "durable_jobs" not in tables:
        op.create_table(
            "durable_jobs",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("job_type", sa.String(160), nullable=False),
            sa.Column("schema_version", sa.String(32), nullable=False, server_default="1"),
            sa.Column("idempotency_key", sa.String(255), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("lease_owner", sa.String(255), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("cancellation_requested_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error_code", sa.String(100), nullable=True),
            sa.Column("result_metadata", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("org_id", "idempotency_key", name="uq_durable_jobs_org_idempotency"),
            sa.CheckConstraint("attempts >= 0", name="ck_durable_jobs_attempts_nonnegative"),
            sa.CheckConstraint("max_attempts >= 1", name="ck_durable_jobs_max_attempts_positive"),
            sa.CheckConstraint(
                "status IN ('pending','running','retry_wait','succeeded','failed','dead_letter','cancelled')",
                name="ck_durable_jobs_status",
            ),
        )
        op.create_index("ix_durable_jobs_org_id", "durable_jobs", ["org_id"])
        op.create_index("ix_durable_jobs_available_at", "durable_jobs", ["available_at"])
        op.create_index("ix_durable_jobs_claim", "durable_jobs", ["status", "available_at", "created_at"])
        op.create_index("ix_durable_jobs_org_created", "durable_jobs", ["org_id", "created_at"])

    tables = set(sa.inspect(bind).get_table_names())
    if "outbox_events" not in tables:
        op.create_table(
            "outbox_events",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("aggregate_type", sa.String(100), nullable=False),
            sa.Column("aggregate_id", sa.String(255), nullable=False),
            sa.Column("event_type", sa.String(160), nullable=False),
            sa.Column("schema_version", sa.String(32), nullable=False, server_default="1"),
            sa.Column("idempotency_key", sa.String(255), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("lease_owner", sa.String(255), nullable=True),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error_code", sa.String(100), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("org_id", "idempotency_key", name="uq_outbox_org_idempotency"),
            sa.CheckConstraint(
                "status IN ('pending','publishing','published','dead_letter')",
                name="ck_outbox_events_status",
            ),
        )
        op.create_index("ix_outbox_events_org_id", "outbox_events", ["org_id"])
        op.create_index("ix_outbox_events_available_at", "outbox_events", ["available_at"])
        op.create_index("ix_outbox_events_claim", "outbox_events", ["status", "available_at", "created_at"])
        op.create_index("ix_outbox_events_org_created", "outbox_events", ["org_id", "created_at"])

    if bind.dialect.name == "postgresql":
        for table in ("durable_jobs", "outbox_events"):
            op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
            op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
            policy = f"tenant_isolation_{table}"
            existing = bind.execute(sa.text(
                "SELECT 1 FROM pg_policies WHERE schemaname = current_schema() AND tablename = :table AND policyname = :policy"
            ), {"table": table, "policy": policy}).first()
            if not existing:
                op.execute(sa.text(
                    f'CREATE POLICY "{policy}" ON "{table}" '
                    'USING ("org_id"::text = current_setting(\'app.current_org_id\', true)) '
                    'WITH CHECK ("org_id"::text = current_setting(\'app.current_org_id\', true))'
                ))


def downgrade():
    raise RuntimeError(
        "Queue and outbox records are operational evidence; use a reviewed backup-and-restore procedure."
    )
