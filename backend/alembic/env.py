from logging.config import fileConfig
import asyncio
from alembic import context
from sqlalchemy import pool, inspect, text, String, Column, MetaData, Table
from sqlalchemy.ext.asyncio import async_engine_from_config
from core.config import settings
from core.database import Base
import models  # noqa: F401 — register all mapped tables

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL.replace("%", "%%"))
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    # This chain performs live-schema inspection and reflection-based batch
    # migrations. Emitting a static SQL script would be incomplete/misleading.
    # Fail explicitly rather than handing operators SQL that cannot be applied.
    raise RuntimeError(
        "Offline SQL generation is unsupported for this migration chain; "
        "run Alembic online against the reviewed target database."
    )


def do_run_migrations(connection) -> None:
    # Alembic's default version_num column is VARCHAR(32), but our descriptive
    # revision identifiers exceed that limit. Widen the bookkeeping column
    # before Alembic attempts to record a revision. This is additive/safe for
    # existing values and preserves immutable migration identifiers.
    inspector = inspect(connection)
    if "alembic_version" not in inspector.get_table_names():
        metadata = MetaData()
        Table(
            "alembic_version",
            metadata,
            Column("version_num", String(64), primary_key=True, nullable=False),
        ).create(connection)
    else:
        version_columns = {column["name"]: column for column in inspector.get_columns("alembic_version")}
        version_column = version_columns.get("version_num")
        if version_column is None:
            raise RuntimeError("alembic_version table is missing its version_num column")
        if connection.dialect.name == "postgresql":
            connection.execute(text(
                "ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(64)"
            ))
        elif connection.dialect.name == "sqlite" and getattr(version_column["type"], "length", None) != 64:
            # SQLite does not enforce VARCHAR lengths; no rebuild is necessary.
            pass
    # Schema inspection and the preflight ALTER/CREATE above may start an
    # implicit SQLAlchemy transaction. Commit that bookkeeping transaction
    # before Alembic opens its own migration transaction; otherwise the
    # connection context can roll back the schema migrations on close.
    connection.commit()
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
