"""Aurontra — FastAPI application entry point."""
import logging
import asyncio
from fastapi import Request
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from core.database import init_db
from core.auth import verify_bearer_token, AuthenticationProviderUnavailable, AuthorizationDenied, authorize_claims
from urllib.parse import urlparse

# Deliberately false until durable tenant-scoped repositories and isolation tests land.
TENANT_ISOLATION_IMPLEMENTED = False
import models  # noqa: F401 — register SQLAlchemy models before metadata creation
from api.routes import (
    health, tickets, devices, resilience,
    automation, threats, billing, reports,
    onboarding, kb, sla, organizations, agent,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s v%s", settings.APP_NAME, settings.VERSION)
    await init_db()
    logger.info("Database initialised")
    yield
    logger.info("Shutting down %s", settings.APP_NAME)


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="IT service operations, resilience analysis, and governed remediation orchestration.",
    lifespan=lifespan,
)

@app.middleware("http")
async def enforce_auth_and_data_plane(request: Request, call_next):
    """Default-deny business APIs until authentication and tenant isolation are configured."""
    path = request.url.path
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        raw_length = request.headers.get("content-length")
        if raw_length is not None:
            try:
                body_length = int(raw_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length.", "code": "INVALID_CONTENT_LENGTH"})
            if body_length < 0:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length.", "code": "INVALID_CONTENT_LENGTH"})
            if body_length > settings.MAX_REQUEST_BODY_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body exceeds the configured limit.", "code": "REQUEST_BODY_TOO_LARGE"})
    if path == "/health/live" or request.method == "OPTIONS":
        return await call_next(request)
    if settings.ENVIRONMENT.lower() == "production" and settings.TEST_MODE:
        return JSONResponse(status_code=503, content={"detail": "Test mode is forbidden in production.", "code": "PRODUCTION_TEST_MODE_FORBIDDEN"})
    if settings.ENVIRONMENT.lower() == "production" and settings.AUTH_MODE == "disabled":
        return JSONResponse(status_code=503, content={"detail": "Authentication cannot be disabled in production.", "code": "PRODUCTION_AUTH_REQUIRED"})
    agent_endpoint = path.startswith("/agent/v1/")
    if agent_endpoint:
        if not settings.AGENT_AUTH_ENABLED:
            return JSONResponse(status_code=503, content={"detail": "Endpoint-agent authentication is disabled.", "code": "AGENT_AUTH_DISABLED"})
        if not (settings.AGENT_JWKS_URL and settings.AGENT_JWT_ISSUER and settings.AGENT_JWT_AUDIENCE):
            return JSONResponse(status_code=503, content={"detail": "Agent identity provider is not configured.", "code": "AGENT_IDENTITY_NOT_CONFIGURED"})
        if settings.ENVIRONMENT.lower() == "production":
            agent_origin = urlparse(settings.AGENT_PUBLIC_ORIGIN)
            if agent_origin.scheme != "https" or not agent_origin.hostname or agent_origin.username or agent_origin.password or agent_origin.path not in {"", "/"} or agent_origin.query or agent_origin.fragment:
                return JSONResponse(status_code=503, content={"detail": "Production agent public origin must be a canonical HTTPS origin.", "code": "AGENT_ORIGIN_INVALID"})
            agent_jwks = urlparse(settings.AGENT_JWKS_URL)
            agent_issuer = urlparse(settings.AGENT_JWT_ISSUER)
            if agent_jwks.scheme != "https" or not agent_jwks.hostname or agent_issuer.scheme != "https" or not agent_issuer.hostname:
                return JSONResponse(status_code=503, content={"detail": "Production agent issuer and JWKS must use HTTPS.", "code": "AGENT_IDENTITY_CONFIG_INVALID"})
    signature_only = path == "/billing/webhook"
    if settings.AUTH_MODE != "disabled" and not signature_only and not agent_endpoint:
        if not (settings.JWT_JWKS_URL and settings.JWT_ISSUER and settings.JWT_AUDIENCE):
            return JSONResponse(status_code=503, content={"detail": "Business API unavailable: authentication provider is not configured.", "code": "AUTH_PROVIDER_NOT_CONFIGURED"})
        if settings.ENVIRONMENT.lower() == "production":
            jwks = urlparse(settings.JWT_JWKS_URL)
            issuer = urlparse(settings.JWT_ISSUER)
            if jwks.scheme != "https" or not jwks.hostname or issuer.scheme != "https" or not issuer.hostname:
                return JSONResponse(status_code=503, content={"detail": "Production JWT issuer and JWKS endpoints must use HTTPS.", "code": "AUTH_PROVIDER_CONFIG_INVALID"})
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return JSONResponse(status_code=401, headers={"WWW-Authenticate": "Bearer"}, content={"detail": "Bearer authentication required.", "code": "AUTHENTICATION_REQUIRED"})
        try:
            claims = await asyncio.to_thread(verify_bearer_token, authorization[7:].strip())
        except AuthenticationProviderUnavailable:
            return JSONResponse(status_code=503, content={"detail": "Authentication provider is temporarily unavailable.", "code": "AUTH_PROVIDER_UNAVAILABLE"})
        except Exception:
            return JSONResponse(status_code=401, headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}, content={"detail": "Invalid or expired access token.", "code": "INVALID_TOKEN"})
        try:
            principal = authorize_claims(claims, request.method, path)
        except AuthorizationDenied as exc:
            return JSONResponse(status_code=403, content={"detail": str(exc), "code": "AUTHORIZATION_DENIED"})
        request.state.tenant_id = principal["tenant_id"]
        request.state.subject = principal["subject"]
        request.state.role = principal["role"]
        request.state.claims = claims
    # Deterministic identity is permitted only in explicit test mode.
    if settings.TEST_MODE and not agent_endpoint and not getattr(request.state, "tenant_id", None):
        request.state.tenant_id = "test-tenant"
        request.state.subject = "test-runner"
        request.state.role = "org:owner"
    # Authentication alone does not fix cross-tenant in-memory storage.
    if not settings.DATA_PLANE_ENABLED or (not TENANT_ISOLATION_IMPLEMENTED and not settings.TEST_MODE):
        return JSONResponse(status_code=503, content={"detail": "Business API is disabled until durable tenant isolation is enabled.", "code": "TENANT_DATA_PLANE_NOT_READY"})
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization", "Content-Type", "X-Request-ID", "DPoP", "X-Aurontra-Agent-Version",
        "X-Tinlance-API-Version", "Idempotency-Key", "traceparent",
    ],
)

# Core
app.include_router(health.router,      prefix="/health",      tags=["health"])
app.include_router(tickets.router,     prefix="/tickets",     tags=["tickets"])
app.include_router(devices.router,     prefix="/devices",     tags=["devices"])
app.include_router(resilience.router,  prefix="/resilience",  tags=["resilience"])
app.include_router(automation.router,  prefix="/automation",  tags=["automation"])
app.include_router(threats.router,     prefix="/threats",     tags=["threats"])

# Sprint 6
app.include_router(billing.router,     prefix="/billing",     tags=["billing"])
app.include_router(reports.router,     prefix="/reports",     tags=["reports"])
app.include_router(onboarding.router,  prefix="/onboarding",  tags=["onboarding"])
app.include_router(organizations.router, prefix="/organizations", tags=["organizations"])
app.include_router(agent.router, prefix="/agent/v1", tags=["endpoint-agent"])

# Gap fills
app.include_router(kb.router,          prefix="/kb",          tags=["knowledge-base"])
app.include_router(sla.router,         prefix="/sla",         tags=["sla"])
