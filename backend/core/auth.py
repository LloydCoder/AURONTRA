"""Strict JWT verification for Aurontra's authenticated API perimeter."""
from __future__ import annotations
from functools import lru_cache
from typing import Any
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
