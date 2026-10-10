"""Bootstrap Aurontra relational schema.

This baseline creates missing tables but does not alter pre-existing tables. Before
adopting an existing deployment, back up the database and compare its schema with
the models; this migration intentionally avoids destructive automatic repair.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "0001_tenant_security_foundation"
down_revision = None
branch_labels = None
depends_on = None


def _tables():
    return set(inspect(op.get_bind()).get_table_names())


def upgrade():
    existing = _tables()
    if "organizations" not in existing:
        op.create_table(
            "organizations",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("name", sa.String(200), nullable=False),
            sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_organizations_status", "organizations", ["status"])
    existing = _tables()
    if "devices" not in existing:
        op.create_table(
            "devices",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("org_id", sa.String(), nullable=False),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("ip_address", sa.String(), nullable=True),
            sa.Column("os_type", sa.String(), nullable=True),
            sa.Column("device_type", sa.String(), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("resilience_score", sa.Integer(), nullable=False, server_default="100"),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_devices_org_id", "devices", ["org_id"])
    existing = _tables()
    if "tickets" not in existing:
        op.create_table(
            "tickets",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("org_id", sa.String(), nullable=False),
            sa.Column("title", sa.String(), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("reporter_email", sa.String(), nullable=False),
            sa.Column("device_id", sa.String(), nullable=True),
            sa.Column("status", sa.Enum("OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED", "ESCALATED", name="ticketstatus"), nullable=False, server_default="OPEN"),
            sa.Column("priority", sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="ticketpriority"), nullable=False, server_default="MEDIUM"),
            sa.Column("source", sa.Enum("EMAIL", "WEBHOOK", "MANUAL", "AGENT", name="ticketsource"), nullable=True, server_default="MANUAL"),
            sa.Column("ai_resolved", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("ai_response", sa.Text(), nullable=True),
            sa.Column("ai_model_used", sa.String(), nullable=True),
            sa.Column("ai_confidence", sa.String(), nullable=True),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_tickets_org_id", "tickets", ["org_id"])
    existing = _tables()
    if "resilience_scores" not in existing:
        op.create_table(
            "resilience_scores",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("device_id", sa.String(), nullable=False),
            sa.Column("score", sa.Integer(), nullable=False, server_default="100"),
            sa.Column("cpu_score", sa.Integer(), nullable=True),
            sa.Column("memory_score", sa.Integer(), nullable=True),
            sa.Column("disk_score", sa.Integer(), nullable=True),
            sa.Column("threat_score", sa.Integer(), nullable=True),
            sa.Column("uptime_score", sa.Integer(), nullable=True),
            sa.Column("predicted_score_72h", sa.Integer(), nullable=True),
            sa.Column("anomaly_detected", sa.Integer(), nullable=True, server_default="0"),
            sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.func.now()),
        )
        op.create_index("ix_resilience_scores_device_id", "resilience_scores", ["device_id"])
    existing = _tables()
    if "automation_rules" not in existing:
        op.create_table(
            "automation_rules",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("org_id", sa.String(), nullable=False),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("trigger_metric", sa.String(), nullable=False),
            sa.Column("trigger_threshold", sa.Float(), nullable=False),
            sa.Column("trigger_operator", sa.String(), nullable=True, server_default="gt"),
            sa.Column("playbook", sa.String(), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("execution_count", sa.Float(), nullable=True, server_default="0"),
            sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.func.now()),
        )
        op.create_index("ix_automation_rules_org_id", "automation_rules", ["org_id"])
    existing = _tables()
    if "api_keys" not in existing:
        op.create_table(
            "api_keys",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
            sa.Column("key_hash", sa.String(128), nullable=False),
            sa.Column("key_prefix", sa.String(24), nullable=False),
            sa.Column("scopes", sa.JSON(), nullable=False),
            sa.Column("created_by", sa.String(255), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
        )
        op.create_index("ix_api_keys_org_id", "api_keys", ["org_id"])
        op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"])
    existing = _tables()
    if "audit_events" not in existing:
        op.create_table(
            "audit_events",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("sequence", sa.Integer(), nullable=False),
            sa.Column("actor_subject", sa.String(255), nullable=False),
            sa.Column("event_type", sa.String(160), nullable=False),
            sa.Column("resource_type", sa.String(100), nullable=False),
            sa.Column("resource_id", sa.String(255), nullable=False),
            sa.Column("request_id", sa.String(128), nullable=True),
            sa.Column("event_data", sa.JSON(), nullable=False),
            sa.Column("previous_hash", sa.String(64), nullable=False),
            sa.Column("event_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("org_id", "sequence", name="uq_audit_events_org_sequence"),
        )
        op.create_index("ix_audit_events_org_created", "audit_events", ["org_id", "created_at"])
        op.create_index("ix_audit_events_org_sequence", "audit_events", ["org_id", "sequence"])
        op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"])
    existing = _tables()
    if "webhook_events" not in existing:
        op.create_table(
            "webhook_events",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("provider", sa.String(80), nullable=False),
            sa.Column("event_id", sa.String(255), nullable=False),
            sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True),
            sa.Column("payload_sha256", sa.String(64), nullable=False),
            sa.Column("status", sa.String(32), nullable=False, server_default="received"),
            sa.Column("payload_metadata", sa.JSON(), nullable=False),
            sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error_code", sa.String(100), nullable=True),
            sa.UniqueConstraint("provider", "event_id", name="uq_webhook_provider_event"),
        )
        op.create_index("ix_webhook_events_org_id", "webhook_events", ["org_id"])
        op.create_index("ix_webhook_events_status", "webhook_events", ["status"])


def downgrade():
    # Non-destructive baseline downgrade: do not drop pre-existing tenant/business data.
    # Use a reviewed backup-and-restore procedure for schema rollback in production.
    for table in ("webhook_events", "audit_events", "api_keys", "organizations"):
        if table in _tables():
            op.drop_table(table)
