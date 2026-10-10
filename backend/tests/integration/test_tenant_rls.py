"""Integration test for PostgreSQL tenant RLS using a non-owner, non-bypass role."""
import os
import uuid

import asyncpg
import pytest


@pytest.mark.asyncio
async def test_rls_scopes_organization_and_device_rows_and_rejects_cross_tenant_write():
    dsn = os.getenv("TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("TEST_POSTGRES_DSN is not configured")

    suffix = uuid.uuid4().hex[:8]
    org_a = f"rls-a-{suffix}"
    org_b = f"rls-b-{suffix}"
    device_a = f"device-a-{suffix}"
    device_b = f"device-b-{suffix}"
    role = f"aurontra_rls_{suffix}"
    password = f"test-{suffix}-only"
    admin = await asyncpg.connect(dsn)
    app = None
    try:
        await admin.execute(f'CREATE ROLE "{role}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS')
        await admin.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
        await admin.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, devices TO "{role}"')
        await admin.execute(
            "INSERT INTO organizations (id, name, status) VALUES ($1, $1, 'active'), ($2, $2, 'active')",
            org_a, org_b,
        )
        await admin.execute(
            "INSERT INTO devices (id, org_id, name) VALUES ($1, $2, $1), ($3, $4, $3)",
            device_a, org_a, device_b, org_b,
        )

        app_dsn = dsn.replace("postgresql://postgres:postgres@", f"postgresql://{role}:{password}@")
        app = await asyncpg.connect(app_dsn)
        await app.execute("SELECT set_config('app.current_org_id', $1, false)", org_a)

        visible_devices = await app.fetch("SELECT id FROM devices ORDER BY id")
        assert [row["id"] for row in visible_devices] == [device_a]
        visible_orgs = await app.fetch("SELECT id FROM organizations")
        assert [row["id"] for row in visible_orgs] == [org_a]

        await app.execute("SELECT set_config('app.current_org_id', '', false)")
        assert await app.fetch("SELECT id FROM devices") == []

        await app.execute("SELECT set_config('app.current_org_id', $1, false)", org_a)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app.execute(
                "INSERT INTO devices (id, org_id, name) VALUES ($1, $2, $3)",
                f"forbidden-{suffix}", org_b, "cross-tenant-write",
            )
    finally:
        if app is not None:
            await app.close()
        await admin.execute(f'DROP OWNED BY "{role}"') if role else None
        await admin.execute(f'DROP ROLE IF EXISTS "{role}"')
        await admin.close()
