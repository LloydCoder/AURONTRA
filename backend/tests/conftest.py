"""Isolated database fixture for API tests.

The fixture is intentionally limited to TEST_MODE. Production data is never
dropped or recreated by test helpers.
"""
import pytest_asyncio

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
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        session.add(Organization(id="test-tenant", name="Test Tenant", status="active"))
        await session.commit()
    yield
    await engine.dispose()
