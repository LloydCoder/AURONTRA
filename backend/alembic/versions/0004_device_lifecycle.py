"""Device lifecycle metadata for explicit enrollment and revocation.

No existing device is silently considered cryptographically enrolled. Existing
rows retain NULL enrolled_at and must be explicitly reviewed/re-enrolled.
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_device_lifecycle"
down_revision = "0003_durable_jobs_and_outbox"
branch_labels = None
depends_on = None


def upgrade():
    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns("devices")}
    if "enrolled_at" not in columns:
        op.add_column("devices", sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True))
    if "revoked_at" not in columns:
        op.add_column("devices", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    if "agent_version" not in columns:
        op.add_column("devices", sa.Column("agent_version", sa.String(64), nullable=True))
    # Fail closed for pre-existing devices: no row is trusted as agent-enrolled
    # merely because a legacy flag happened to be active.
    op.execute("UPDATE devices SET is_active = false WHERE enrolled_at IS NULL")
    indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("devices")}
    if "ix_devices_org_active" not in indexes:
        op.create_index("ix_devices_org_active", "devices", ["org_id", "is_active"])


def downgrade():
    raise RuntimeError(
        "Device lifecycle metadata is security-relevant; rollback requires a reviewed backup-and-restore plan."
    )
