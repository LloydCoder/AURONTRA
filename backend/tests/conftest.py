"""Isolated relational state for API tests.

Only TEST_MODE tests may reset records. Schema lifecycle in production remains
owned by reviewed Alembic migrations, never by this fixture.
"""
import pytest_asyncio
from sqlalchemy import delete

from core.config import settings
from core.database import AsyncSessionLocal, Base, engine
import models  # noqa: F401
from models.organization import Organization


@pytest_asyncio.fixture(autouse=True)
async def isolated_tenant_database():
    if not settings.TEST_MODE:
        yield
        return

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        # Delete children before parents; retain the schema between tests to
        # avoid repeated DDL and event-loop/pool churn.
        for table in reversed(Base.metadata.sorted_tables):
            await connection.execute(delete(table))

    async with AsyncSessionLocal() as session:
        session.add(Organization(id="test-tenant", name="Test Tenant", status="active"))
        await session.commit()
    yield
