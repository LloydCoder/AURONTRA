"""Align containment status constraint with the verification state machine.

The ORM introduced awaiting_verification, but the original table migration
omitted it. This forward-only migration updates existing installations without
rewriting historical containment records.
"""
from alembic import op
import sqlalchemy as sa

revision = "0013_containment_awaiting_verification"
down_revision = "0012_telemetry_schema_v2"
branch_labels = None
depends_on = None

CONSTRAINT = "ck_threat_containment_status"
ALLOWED_STATUSES = (
    "'submitting','approval_pending','platform_pending','unknown_outcome',"
    "'awaiting_verification','contained','failed','verification_failed','cancelled'"
)


def upgrade():
    bind = op.get_bind()
    if "threat_containment_attempts" not in sa.inspect(bind).get_table_names():
        raise RuntimeError(
            "threat_containment_attempts must exist before containment status alignment."
        )

    checks = {
        item.get("name"): item.get("sqltext", "")
        for item in sa.inspect(bind).get_check_constraints("threat_containment_attempts")
    }
    current = checks.get(CONSTRAINT, "")
    if "awaiting_verification" in current:
        return

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("threat_containment_attempts", recreate="always") as batch:
            if CONSTRAINT in checks:
                batch.drop_constraint(CONSTRAINT, type_="check")
            batch.create_check_constraint(
                CONSTRAINT,
                f"status IN ({ALLOWED_STATUSES})",
            )
    else:
        if CONSTRAINT in checks:
            op.drop_constraint(CONSTRAINT, "threat_containment_attempts", type_="check")
        op.create_check_constraint(
            CONSTRAINT,
            "threat_containment_attempts",
            f"status IN ({ALLOWED_STATUSES})",
        )


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text(
        "SELECT COUNT(*) FROM threat_containment_attempts "
        "WHERE status = 'awaiting_verification'"
    )).scalar_one():
        raise RuntimeError(
            "Cannot downgrade while awaiting_verification records exist; "
            "resolve or archive those attempts before a reviewed rollback."
        )

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("threat_containment_attempts", recreate="always") as batch:
            batch.drop_constraint(CONSTRAINT, type_="check")
            batch.create_check_constraint(
                CONSTRAINT,
                "status IN ('submitting','approval_pending','platform_pending',"
                "'unknown_outcome','contained','failed','verification_failed','cancelled')",
            )
    else:
        op.drop_constraint(CONSTRAINT, "threat_containment_attempts", type_="check")
        op.create_check_constraint(
            CONSTRAINT,
            "threat_containment_attempts",
            "status IN ('submitting','approval_pending','platform_pending',"
            "'unknown_outcome','contained','failed','verification_failed','cancelled')",
        )
