"""Durable tenant-bound billing checkout intents and subscription state."""
from alembic import op
import sqlalchemy as sa

revision = "0014_billing_checkout_subscriptions"
down_revision = "0013_containment_awaiting_verification"
branch_labels = None
depends_on = None


def _enable_tenant_rls(table: str) -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
    policy = f"tenant_isolation_{table}"
    op.execute(sa.text(
        f'CREATE POLICY "{policy}" ON "{table}" '
        'USING ("org_id"::text = current_setting(\'app.current_org_id\', true)) '
        'WITH CHECK ("org_id"::text = current_setting(\'app.current_org_id\', true))'
    ))


def upgrade():
    op.create_table(
        "billing_checkout_intents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False, server_default="lemonsqueezy"),
        sa.Column("provider_checkout_id", sa.String(128), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("plan_id", sa.String(32), nullable=False),
        sa.Column("variant_id", sa.String(64), nullable=False),
        sa.Column("device_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="creating"),
        sa.Column("checkout_url", sa.String(2048), nullable=True),
        sa.Column("provider_subscription_id", sa.String(128), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(100), nullable=True),
        sa.UniqueConstraint("org_id", "idempotency_key", name="uq_billing_checkout_org_idempotency"),
        sa.UniqueConstraint("provider", "provider_checkout_id", name="uq_billing_checkout_provider_checkout"),
        sa.CheckConstraint(
            "status IN ('creating','pending','unknown_outcome','completed','cancelled','expired','failed')",
            name="ck_billing_checkout_intent_status",
        ),
        sa.CheckConstraint("device_count > 0", name="ck_billing_checkout_device_count_positive"),
    )
    op.create_index("ix_billing_checkout_org_status_created", "billing_checkout_intents", ["org_id", "status", "created_at"])

    op.create_table(
        "billing_subscriptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(64), sa.ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("checkout_intent_id", sa.String(36), sa.ForeignKey("billing_checkout_intents.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False, server_default="lemonsqueezy"),
        sa.Column("provider_subscription_id", sa.String(128), nullable=False),
        sa.Column("provider_customer_id", sa.String(128), nullable=True),
        sa.Column("plan_id", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("renews_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("provider", "provider_subscription_id", name="uq_billing_subscription_provider_id"),
        sa.CheckConstraint(
            "status IN ('active','on_trial','past_due','paused','unpaid','cancelled','expired','unknown')",
            name="ck_billing_subscription_status",
        ),
    )
    op.create_index("ix_billing_subscription_org_status", "billing_subscriptions", ["org_id", "status"])
    _enable_tenant_rls("billing_checkout_intents")
    _enable_tenant_rls("billing_subscriptions")


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS "tenant_isolation_billing_subscriptions" ON billing_subscriptions'))
        op.execute(sa.text('DROP POLICY IF EXISTS "tenant_isolation_billing_checkout_intents" ON billing_checkout_intents'))
    op.drop_index("ix_billing_subscription_org_status", table_name="billing_subscriptions")
    op.drop_table("billing_subscriptions")
    op.drop_index("ix_billing_checkout_org_status_created", table_name="billing_checkout_intents")
    op.drop_table("billing_checkout_intents")
