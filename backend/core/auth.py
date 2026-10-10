"""Strict JWT verification for Aurontra's authenticated API perimeter."""
from __future__ import annotations
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse
import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWTError
from core.config import settings

class AuthenticationProviderUnavailable(RuntimeError):
    """The configured identity provider could not be reached safely."""


@lru_cache(maxsize=1)
def _jwks_client() -> PyJWKClient:
    if not settings.JWT_JWKS_URL:
        raise RuntimeError("JWT_JWKS_URL is not configured")
    return PyJWKClient(settings.JWT_JWKS_URL, cache_jwk_set=True, lifespan=300, timeout=5)

def verify_bearer_token(token: str) -> dict[str, Any]:
    """Verify JWT signature, issuer, audience and expiry; never decode unverified claims."""
    if not settings.JWT_JWKS_URL or not settings.JWT_ISSUER or not settings.JWT_AUDIENCE:
        raise RuntimeError("JWT verification is not configured")
    if not token or len(token) > 16_384:
        raise ValueError("Invalid token size")
    try:
        signing_key = _jwks_client().get_signing_key_from_jwt(token).key
    except PyJWKClientConnectionError as exc:
        raise AuthenticationProviderUnavailable("JWKS provider unavailable") from exc
    claims = jwt.decode(
        token, signing_key, algorithms=["RS256", "ES256"],
        issuer=settings.JWT_ISSUER, audience=settings.JWT_AUDIENCE,
        options={"require": ["exp", "iat", "iss", "aud", "sub"], "verify_signature": True,
                 "verify_exp": True, "verify_iss": True, "verify_aud": True},
        leeway=30,
    )
    if not isinstance(claims, dict):
        raise ValueError("JWT payload must be an object")
    return claims


class AuthorizationDenied(PermissionError):
    """The verified identity lacks a required tenant role."""


_ROLE_RANK = {
    "viewer": 1,
    "org:viewer": 1,
    "member": 2,
    "org:member": 2,
    "admin": 3,
    "org:admin": 3,
    "owner": 3,
    "org:owner": 3,
}


def authorize_claims(claims: dict[str, Any], method: str, path: str) -> dict[str, str]:
    """Validate tenant identity and apply a conservative role policy to an API operation."""
    tenant_id = claims.get("org_id") or claims.get("tenant_id")
    subject = claims.get("sub")
    role = claims.get("org_role") or claims.get("role")
    if not isinstance(tenant_id, str) or not tenant_id or not isinstance(subject, str) or not subject:
        raise AuthorizationDenied("Token must identify a subject and organization")
    if not isinstance(role, str) or role not in _ROLE_RANK:
        raise AuthorizationDenied("Token must contain a recognized organization role")

    normalized_method = method.upper()
    admin_only = (
        path.startswith("/automation/trigger")
        or path.startswith("/threats/block")
        or path.startswith("/billing/checkout")
        or path.startswith("/onboarding/register")
        or normalized_method == "DELETE"
    )
    minimum_rank = 3 if admin_only else (2 if normalized_method in {"POST", "PUT", "PATCH"} else 1)
    if _ROLE_RANK[role] < minimum_rank:
        raise AuthorizationDenied("Organization role is insufficient for this operation")
    return {"tenant_id": tenant_id, "subject": subject, "role": role}
