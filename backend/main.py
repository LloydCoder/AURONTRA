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
from core.auth import verify_bearer_token
import models  # noqa: F401 — register SQLAlchemy models before metadata creation
from api.routes import (
    health, tickets, devices, resilience,
    automation, threats, billing, reports,
    onboarding, kb, sla,
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
    if path == "/health/live" or request.method == "OPTIONS":
        return await call_next(request)
    if settings.AUTH_MODE != "disabled":
        if not (settings.JWT_JWKS_URL and settings.JWT_ISSUER and settings.JWT_AUDIENCE):
            return JSONResponse(status_code=503, content={"detail": "Business API unavailable: authentication provider is not configured.", "code": "AUTH_PROVIDER_NOT_CONFIGURED"})
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return JSONResponse(status_code=401, headers={"WWW-Authenticate": "Bearer"}, content={"detail": "Bearer authentication required.", "code": "AUTHENTICATION_REQUIRED"})
        try:
            claims = await asyncio.to_thread(verify_bearer_token, authorization[7:].strip())
        except Exception:
            return JSONResponse(status_code=401, headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}, content={"detail": "Invalid or expired access token.", "code": "INVALID_TOKEN"})
        tenant_id = claims.get("org_id") or claims.get("tenant_id")
        subject = claims.get("sub")
        if not isinstance(tenant_id, str) or not tenant_id or not isinstance(subject, str) or not subject:
            return JSONResponse(status_code=403, content={"detail": "Token must identify a subject and organization.", "code": "TENANT_CONTEXT_REQUIRED"})
        request.state.tenant_id = tenant_id
        request.state.subject = subject
        request.state.claims = claims
    # Authentication alone does not fix cross-tenant in-memory storage.
    if not settings.DATA_PLANE_ENABLED:
        return JSONResponse(status_code=503, content={"detail": "Business API unavailable until durable tenant isolation is enabled.", "code": "TENANT_DATA_PLANE_NOT_READY"})
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization", "Content-Type", "X-Request-ID",
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

# Gap fills
app.include_router(kb.router,          prefix="/kb",          tags=["knowledge-base"])
app.include_router(sla.router,         prefix="/sla",         tags=["sla"])
