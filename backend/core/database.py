"""Async database engine — schema changes are migration-controlled in production."""
from sqlalchemy import event, inspect, text
from fastapi import Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool
from core.config import settings

_engine_options = {"echo": settings.DEBUG, "future": True}
# TestClient and async tests can use different event loops. Avoid retaining
# async driver connections across loops in test mode.
if settings.TEST_MODE:
    _engine_options["poolclass"] = NullPool
engine = create_async_engine(settings.DATABASE_URL, **_engine_options)


@event.listens_for(engine.sync_engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
    """SQLite disables FK enforcement by default; tests/dev must not silently skip it."""
    if engine.dialect.name == "sqlite":
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields an async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize local schemas; production requires an explicitly applied Alembic revision."""
    if settings.ENVIRONMENT.lower() == "production":
        if not settings.DATA_PLANE_ENABLED:
            # The API remains in closed, health-only mode; do not mutate production schema.
            return
        async with engine.connect() as conn:
            def read_revisions(sync_conn):
                inspector = inspect(sync_conn)
                if "alembic_version" not in inspector.get_table_names():
                    return []
                result = sync_conn.execute(text("SELECT version_num FROM alembic_version"))
                return list(result.scalars().all())
            revisions = await conn.run_sync(read_revisions)
        expected = settings.DB_SCHEMA_REVISION
        if revisions != [expected]:
            raise RuntimeError(
                "Production database migration mismatch: "
                f"expected exactly [{expected!r}], found {revisions!r}. "
                "Run and verify Alembic migrations before enabling the data plane."
            )
        return

    # Development and explicitly configured test environments only.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)



async def get_tenant_db(request: Request):
    """Yield a session bound to the verified tenant and set PostgreSQL RLS context."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if settings.TEST_MODE and not tenant_id:
        tenant_id = "test-tenant"
    if not isinstance(tenant_id, str) or not tenant_id:
        raise HTTPException(status_code=401, detail="Verified tenant context is required.")

    async with AsyncSessionLocal() as session:
        try:
            session.info["tenant_id"] = tenant_id
            if session.get_bind().dialect.name == "postgresql":
                # Transaction-local setting is cleared at commit/rollback; never use a session-wide tenant.
                await session.execute(
                    text("SELECT set_config('app.current_org_id', :tenant_id, true)"),
                    {"tenant_id": tenant_id},
                )
            # An authenticated token may name a deleted, suspended, or legacy
            # tenant. Only explicitly active organizations can access the data plane.
            from models.organization import Organization
            organization = await session.get(Organization, tenant_id)
            if organization is None or organization.status != "active":
                raise HTTPException(status_code=403, detail="Organization is not active.")
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
