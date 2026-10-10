"""Async database engine — schema changes are migration-controlled in production."""
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from core.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG, future=True)
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
