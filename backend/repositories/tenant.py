"""Tenant-scoped query primitives shared by database-backed route repositories."""
from sqlalchemy import select


def tenant_select(model, tenant_id: str):
    """Build a tenant-scoped SELECT; never infer tenant identity from resource input."""
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("A verified tenant ID is required for tenant-scoped queries")
    if not hasattr(model, "org_id"):
        raise TypeError(f"{model.__name__} is not a tenant-owned model")
    return select(model).where(model.org_id == tenant_id)
