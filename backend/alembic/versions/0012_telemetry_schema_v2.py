"""Permit telemetry schema v2 while retaining v1 compatibility."""
from alembic import op
import sqlalchemy as sa

revision = "0012_telemetry_schema_v2"
down_revision = "0011_containment_verification_evidence"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if "telemetry_records" not in sa.inspect(bind).get_table_names():
        raise RuntimeError("telemetry_records must exist before expanding supported schema versions.")

    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("telemetry_records", recreate="always") as batch:
            batch.drop_constraint("ck_telemetry_schema_version", type_="check")
            batch.create_check_constraint(
                "ck_telemetry_schema_version",
                "schema_version IN ('1', '2')",
            )
    else:
        constraints = {
            item.get("name")
            for item in sa.inspect(bind).get_check_constraints("telemetry_records")
        }
        if "ck_telemetry_schema_version" in constraints:
            op.drop_constraint(
                "ck_telemetry_schema_version",
                "telemetry_records",
                type_="check",
            )
        op.create_check_constraint(
            "ck_telemetry_schema_version",
            "telemetry_records",
            "schema_version IN ('1', '2')",
        )


def downgrade():
    bind = op.get_bind()
    if bind.execute(sa.text(
        "SELECT COUNT(*) FROM telemetry_records WHERE schema_version <> '1'"
    )).scalar_one():
        raise RuntimeError(
            "Cannot downgrade while schema-v2 telemetry exists; migrate or archive those records first."
        )
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("telemetry_records", recreate="always") as batch:
            batch.drop_constraint("ck_telemetry_schema_version", type_="check")
            batch.create_check_constraint(
                "ck_telemetry_schema_version",
                "schema_version = '1'",
            )
    else:
        op.drop_constraint("ck_telemetry_schema_version", "telemetry_records", type_="check")
        op.create_check_constraint(
            "ck_telemetry_schema_version",
            "telemetry_records",
            "schema_version = '1'",
        )
