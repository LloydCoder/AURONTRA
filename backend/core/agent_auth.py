"""Platform-issued agent identity verification with DPoP sender constraint.

Aurontra verifies identities and request proofs; it does not mint credentials,
store private keys, or make authorization-policy decisions for the Agent Platform.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
from contextlib import aclosing
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

import jwt
from fastapi import Depends, HTTPException, Request
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWTError

from core.config import settings


_ALLOWED_DPOP_ALGORITHMS = frozenset({"ES256", "RS256", "EdDSA"})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_NORMALIZED_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    tenant_id: str
    device_id: str
    scopes: frozenset[str]
    token_id: str
    key_thumbprint: str
    proof_jti: str
    request_hash: str


@lru_cache(maxsize=1)
def _agent_jwks_client() -> PyJWKClient:
    if not settings.AGENT_JWKS_URL:
        raise RuntimeError("AGENT_JWKS_URL is not configured")
    return PyJWKClient(settings.AGENT_JWKS_URL, cache_jwk_set=True, lifespan=300, timeout=5)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk_data: dict[str, Any]) -> str:
    """Compute an RFC 7638 JWK thumbprint from the required public members only."""
    kty = jwk_data.get("kty")
    if kty == "EC":
        names = ("crv", "kty", "x", "y")
    elif kty == "RSA":
        names = ("e", "kty", "n")
    elif kty == "OKP":
        names = ("crv", "kty", "x")
    else:
        raise ValueError("unsupported DPoP public key type")
    if any(not isinstance(jwk_data.get(name), str) or not jwk_data[name] for name in names):
        raise ValueError("DPoP JWK is missing required public members")
    canonical = json.dumps(
        {name: jwk_data[name] for name in names},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return _b64url(sha256(canonical).digest())


def _verify_access_token(token: str) -> dict[str, Any]:
    if not settings.AGENT_JWKS_URL or not settings.AGENT_JWT_ISSUER or not settings.AGENT_JWT_AUDIENCE:
        raise RuntimeError("agent identity provider is not configured")
    if not token or len(token) > 16_384 or any(character.isspace() for character in token):
        raise ValueError("invalid access token")
    key = _agent_jwks_client().get_signing_key_from_jwt(token).key
    claims = jwt.decode(
        token,
        key,
        algorithms=["RS256", "ES256", "EdDSA"],
        issuer=settings.AGENT_JWT_ISSUER,
        audience=settings.AGENT_JWT_AUDIENCE,
        options={"require": ["exp", "iat", "iss", "aud", "sub", "jti", "cnf"]},
        leeway=settings.AGENT_CLOCK_SKEW_SECONDS,
    )
    if not isinstance(claims, dict):
        raise ValueError("agent access token payload must be an object")
    now = datetime.now(timezone.utc).timestamp()
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, (int, float))
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or issued_at > now + settings.AGENT_CLOCK_SKEW_SECONDS
        or expires_at - issued_at > settings.AGENT_ACCESS_TOKEN_MAX_TTL_SECONDS
    ):
        raise ValueError("agent access token validity window is invalid")
    for name, limit in (("sub", 128), ("jti", 256)):
        value = claims.get(name)
        if not isinstance(value, str) or not value or value != value.strip() or len(value) > limit or not _NORMALIZED_ID.fullmatch(value):
            raise ValueError(f"agent access token claim {name!r} is invalid")
    tenant_id = claims.get("tenant_id", claims.get("org_id"))
    if not isinstance(tenant_id, str) or not tenant_id or tenant_id != tenant_id.strip() or len(tenant_id) > 64 or not _NORMALIZED_ID.fullmatch(tenant_id):
        raise ValueError("agent access token tenant claim is invalid")
    raw_scope = claims.get("scope", claims.get("scp", ""))
    if isinstance(raw_scope, str):
        scopes = [item for item in raw_scope.split() if item]
    elif isinstance(raw_scope, list) and all(isinstance(item, str) for item in raw_scope):
        scopes = raw_scope
    else:
        raise ValueError("agent access token scopes are malformed")
    if any(not item or item != item.strip() for item in scopes):
        raise ValueError("agent access token scopes are not normalized")
    cnf = claims.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jkt"), str) or not cnf["jkt"]:
        raise ValueError("agent access token must be sender-constrained with cnf.jkt")
    return claims


def _expected_htu(request: Request) -> str:
    if settings.AGENT_PUBLIC_ORIGIN:
        origin = settings.AGENT_PUBLIC_ORIGIN.rstrip("/")
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise RuntimeError("AGENT_PUBLIC_ORIGIN must be an absolute origin without path, query, or userinfo")
        if settings.ENVIRONMENT.lower() == "production" and parsed.scheme != "https":
            raise RuntimeError("AGENT_PUBLIC_ORIGIN must use HTTPS in production")
    elif settings.TEST_MODE or settings.ENVIRONMENT.lower() != "production":
        origin = str(request.base_url).rstrip("/")
    else:
        raise RuntimeError("AGENT_PUBLIC_ORIGIN is required in production")

    raw_path = request.scope.get("raw_path")
    path = raw_path.decode("ascii") if isinstance(raw_path, bytes) else request.url.path
    if not path.startswith("/") or "?" in path or "#" in path:
        raise ValueError("request path is invalid for DPoP verification")
    return origin + path


def _verify_dpop_proof(
    proof: str,
    *,
    access_token: str,
    request: Request,
    body: bytes,
    token_claims: dict[str, Any],
) -> tuple[str, str]:
    if not proof or len(proof) > 16_384 or any(character.isspace() for character in proof):
        raise ValueError("DPoP proof is missing or malformed")
    header = jwt.get_unverified_header(proof)
    algorithm = header.get("alg")
    if header.get("typ") != "dpop+jwt" or algorithm not in _ALLOWED_DPOP_ALGORITHMS:
        raise ValueError("DPoP proof type or algorithm is not allowed")
    jwk_data = header.get("jwk")
    if not isinstance(jwk_data, dict) or _PRIVATE_JWK_MEMBERS.intersection(jwk_data):
        raise ValueError("DPoP proof must contain a public-only JWK")
    key_type = jwk_data.get("kty")
    if (algorithm == "ES256" and (key_type != "EC" or jwk_data.get("crv") != "P-256")) or (
        algorithm == "RS256" and key_type != "RSA"
    ) or (algorithm == "EdDSA" and (key_type != "OKP" or jwk_data.get("crv") != "Ed25519")):
        raise ValueError("DPoP key type does not match the signature algorithm")
    thumbprint = jwk_thumbprint(jwk_data)
    cnf = token_claims.get("cnf")
    if not isinstance(cnf, dict) or cnf.get("jkt") != thumbprint:
        raise ValueError("DPoP public key does not match the sender-constrained access token")

    public_key = jwt.PyJWK.from_dict({**jwk_data, "alg": algorithm}, algorithm=algorithm).key
    if algorithm == "RS256" and getattr(public_key, "key_size", 0) < 2048:
        raise ValueError("DPoP RSA keys must be at least 2048 bits")
    proof_claims = jwt.decode(
        proof,
        public_key,
        algorithms=[algorithm],
        options={"verify_aud": False, "verify_exp": False, "verify_iat": False, "verify_iss": False},
    )
    if not isinstance(proof_claims, dict):
        raise ValueError("DPoP proof payload must be an object")

    if proof_claims.get("htm") != request.method.upper() or proof_claims.get("htu") != _expected_htu(request):
        raise ValueError("DPoP proof is bound to a different HTTP request")
    issued_at = proof_claims.get("iat")
    now = datetime.now(timezone.utc).timestamp()
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, (int, float))
        or issued_at < now - settings.AGENT_DPOP_MAX_AGE_SECONDS
        or issued_at > now + settings.AGENT_CLOCK_SKEW_SECONDS
    ):
        raise ValueError("DPoP proof is outside the accepted time window")
    proof_jti = proof_claims.get("jti")
    if not isinstance(proof_jti, str) or proof_jti != proof_jti.strip() or not 16 <= len(proof_jti) <= 256 or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in proof_jti):
        raise ValueError("DPoP proof identifier is invalid")
    expected_ath = _b64url(sha256(access_token.encode("ascii")).digest())
    if proof_claims.get("ath") != expected_ath:
        raise ValueError("DPoP proof access-token hash does not match")
    expected_body_hash = _b64url(sha256(body).digest())
    if proof_claims.get("bht") != expected_body_hash:
        raise ValueError("DPoP proof body hash does not match")
    return proof_jti, sha256(body).hexdigest()


async def get_agent_identity(request: Request) -> AgentIdentity:
    """Authenticate a Platform-issued DPoP-bound access token for this exact request."""
    if not settings.AGENT_AUTH_ENABLED:
        raise HTTPException(status_code=503, detail="Endpoint-agent authentication is disabled.")
    authorization = request.headers.get("Authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "dpop" or not separator:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "DPoP"}, detail="DPoP authorization required.")
    token = token.strip()
    proof = request.headers.get("DPoP", "")
    try:
        claims = await asyncio.to_thread(_verify_access_token, token)
        proof_jti, request_hash = _verify_dpop_proof(
            proof,
            access_token=token,
            request=request,
            body=await request.body(),
            token_claims=claims,
        )
    except (PyJWKClientConnectionError, TimeoutError) as exc:
        raise HTTPException(status_code=503, detail="Agent identity provider is temporarily unavailable.") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Agent identity configuration is unavailable.") from exc
    except (PyJWTError, ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": 'DPoP error="invalid_dpop_proof"'}, detail="Invalid agent identity or DPoP proof.") from exc

    tenant_id = claims.get("tenant_id", claims.get("org_id"))
    identity = AgentIdentity(
        tenant_id=tenant_id,
        device_id=claims["sub"],
        scopes=frozenset(claims.get("scope", claims.get("scp", "")).split())
        if isinstance(claims.get("scope", claims.get("scp", "")), str)
        else frozenset(claims.get("scope", claims.get("scp", []))),
        token_id=claims["jti"],
        key_thumbprint=claims["cnf"]["jkt"],
        proof_jti=proof_jti,
        request_hash=request_hash,
    )
    request.state.tenant_id = identity.tenant_id
    request.state.subject = identity.device_id
    request.state.role = "agent"
    request.state.agent_identity = identity
    return identity



async def get_agent_tenant_db(request: Request, identity: AgentIdentity = Depends(get_agent_identity)):
    """Resolve agent identity first, then open a tenant-scoped business session."""
    from core.database import get_tenant_db

    dependency = get_tenant_db(request)
    async with aclosing(dependency) as generator:
        async for session in generator:
            yield session
