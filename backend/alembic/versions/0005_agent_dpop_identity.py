"""Platform-bound DPoP identity and durable request replay protection."""
from alembic import op
import sqlalchemy as sa

revision = "0005_agent_dpop_identity"
down_revision = "0004_device_lifecycle"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {item["name"] for item in inspector.get_columns("devices")}
    if "agent_key_thumbprint" not in columns:
        op.add_column("devices", sa.Column("agent_key_thumbprint", sa.String(128), nullable=True))

    tables = set(sa.inspect(bind).get_table_names())
    if "agent_request_replays" not in tables:
        op.create_table(
            "agent_request_replays",
            sa.Column("jti", sa.String(256), primary_key=True),
            sa.Column("org_id", sa.String(64), nullable=False),
            sa.Column("device_id", sa.String(128), nullable=False),
            sa.Column("request_hash", sa.String(64), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(
                ["org_id", "device_id"],
                ["devices.org_id", "devices.id"],
                name="fk_agent_request_replays_org_device",
                ondelete="RESTRICT",
            ),
        )
        op.create_index(
            "ix_agent_request_replays_expires_at",
            "agent_request_replays",
            ["expires_at"],
        )
        op.create_index(
            "ix_agent_request_replays_org_device",
            "agent_request_replays",
            ["org_id", "device_id"],
        )

    if bind.dialect.name == "postgresql":
        op.execute(sa.text('ALTER TABLE "agent_request_replays" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "agent_request_replays" FORCE ROW LEVEL SECURITY'))
        existing = bind.execute(sa.text(
            "SELECT 1 FROM pg_policies WHERE schemaname = current_schema() "
            "AND tablename = 'agent_request_replays' AND policyname = 'tenant_isolation_agent_request_replays'"
        )).first()
        if not existing:
            op.execute(sa.text(
                'CREATE POLICY "tenant_isolation_agent_request_replays" ON "agent_request_replays" '
                'USING ("org_id"::text = current_setting(\'app.current_org_id\', true)) '
                'WITH CHECK ("org_id"::text = current_setting(\'app.current_org_id\', true))'
            ))


def downgrade():
    raise RuntimeError(
        "Agent replay records are security evidence; use a reviewed backup-and-restore procedure."
    )
