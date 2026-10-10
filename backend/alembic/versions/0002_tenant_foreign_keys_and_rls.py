"""Tenant ownership constraints and PostgreSQL row-level security.

Existing organization IDs are preserved as inactive records requiring review.
Orphaned resilience-score rows abort the migration rather than being guessed.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, text

revision = "0002_tenant_foreign_keys_and_rls"
down_revision = "0001_tenant_security_foundation"
branch_labels = None
depends_on = None


def _inspector():
    return inspect(op.get_bind())


def _tables():
    return set(_inspector().get_table_names())


def _columns(table):
    return {item["name"] for item in _inspector().get_columns(table)}


def _foreign_keys(table):
    return {item.get("name") for item in _inspector().get_foreign_keys(table)}


def _unique_constraints(table):
    return {item.get("name") for item in _inspector().get_unique_constraints(table)}


def _seed_legacy_organizations():
    bind = op.get_bind()
    existing_tables = _tables()
    sources = [table for table in ("devices", "tickets", "automation_rules") if table in existing_tables and "org_id" in _columns(table)]
    organization_ids = set()
    for table in sources:
        organization_ids.update(bind.execute(text(f"SELECT DISTINCT org_id FROM {table} WHERE org_id IS NOT NULL")).scalars().all())
    for org_id in sorted(organization_ids):
        if not isinstance(org_id, str) or not org_id.strip() or len(org_id) > 64:
            raise RuntimeError(f"Invalid legacy organization identifier in data: {org_id!r}")
        exists = bind.execute(text("SELECT 1 FROM organizations WHERE id = :org_id"), {"org_id": org_id}).first()
        if not exists:
            bind.execute(
                text("INSERT INTO organizations (id, name, status) VALUES (:id, :name, 'legacy_review_required')"),
                {"id": org_id, "name": org_id[:200]},
            )


def _add_fk(table, name, local_cols, remote_table, remote_cols, ondelete="RESTRICT"):
    if name in _foreign_keys(table):
        return
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(table, recreate="always") as batch:
            batch.create_foreign_key(name, remote_table, local_cols, remote_cols, ondelete=ondelete)
    else:
        op.create_foreign_key(name, table, remote_table, local_cols, remote_cols, ondelete=ondelete)


def _add_unique(table, name, columns):
    if name in _unique_constraints(table):
        return
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(table, recreate="always") as batch:
            batch.create_unique_constraint(name, columns)
    else:
        op.create_unique_constraint(name, table, columns)


def upgrade():
    _seed_legacy_organizations()
    if "org_id" not in _columns("resilience_scores"):
        op.add_column("resilience_scores", sa.Column("org_id", sa.String(64), nullable=True))
    bind = op.get_bind()
    bind.execute(text(
        "UPDATE resilience_scores SET org_id = "
        "(SELECT devices.org_id FROM devices WHERE devices.id = resilience_scores.device_id) "
        "WHERE org_id IS NULL"
    ))
    orphan_count = bind.execute(text("SELECT COUNT(*) FROM resilience_scores WHERE org_id IS NULL")).scalar_one()
    if orphan_count:
        raise RuntimeError(
            f"Migration stopped: {orphan_count} resilience score rows have no matching tenant-owned device. "
            "Resolve orphan rows explicitly before retrying."
        )

    # Ensure every org ID referenced by business tables has a reviewed organization row.
    _seed_legacy_organizations()

    _add_unique("devices", "uq_devices_org_id_id", ["org_id", "id"])
    _add_fk("devices", "fk_devices_org", ["org_id"], "organizations", ["id"])
    _add_fk("tickets", "fk_tickets_org", ["org_id"], "organizations", ["id"])
    _add_fk("tickets", "fk_tickets_org_device", ["org_id", "device_id"], "devices", ["org_id", "id"])
    _add_fk("automation_rules", "fk_automation_rules_org", ["org_id"], "organizations", ["id"])

    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("resilience_scores", recreate="always") as batch:
            batch.alter_column("org_id", existing_type=sa.String(64), nullable=False)
            if "fk_resilience_scores_org" not in _foreign_keys("resilience_scores"):
                batch.create_foreign_key("fk_resilience_scores_org", "organizations", ["org_id"], ["id"], ondelete="RESTRICT")
            if "fk_resilience_scores_org_device" not in _foreign_keys("resilience_scores"):
                batch.create_foreign_key("fk_resilience_scores_org_device", "devices", ["org_id", "device_id"], ["org_id", "id"], ondelete="RESTRICT")
    else:
        if "fk_resilience_scores_org" not in _foreign_keys("resilience_scores"):
            op.create_foreign_key("fk_resilience_scores_org", "resilience_scores", "organizations", ["org_id"], ["id"], ondelete="RESTRICT")
        if "fk_resilience_scores_org_device" not in _foreign_keys("resilience_scores"):
            op.create_foreign_key("fk_resilience_scores_org_device", "resilience_scores", "devices", ["org_id", "device_id"], ["org_id", "id"], ondelete="RESTRICT")
        op.alter_column("resilience_scores", "org_id", existing_type=sa.String(64), nullable=False)

    if op.get_bind().dialect.name == "postgresql":
        # The application role must not be superuser or BYPASSRLS. Webhook inbox
        # is intentionally excluded; it requires a separate worker role/policy.
        policies = {
            "organizations": ("id",),
            "devices": ("org_id",),
            "tickets": ("org_id",),
            "resilience_scores": ("org_id",),
            "automation_rules": ("org_id",),
            "api_keys": ("org_id",),
            "audit_events": ("org_id",),
        }
        for table, (tenant_column,) in policies.items():
            op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
            op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
            policy = f"tenant_isolation_{table}"
            op.execute(sa.text(
                f'CREATE POLICY "{policy}" ON "{table}" '
                f'USING ("{tenant_column}"::text = current_setting(\'app.current_org_id\', true)) '
                f'WITH CHECK ("{tenant_column}"::text = current_setting(\'app.current_org_id\', true))'
            ))


def downgrade():
    raise RuntimeError(
        "Tenant constraints and RLS are intentionally not auto-reversed. Use a reviewed backup-and-restore plan."
    )
