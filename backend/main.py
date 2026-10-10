"""Aurontra — FastAPI application entry point."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from core.database import init_db
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
    logger.info("[ResilientAI] Shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="IT service operations, resilience analysis, and governed remediation orchestration.",
    lifespan=lifespan,
)

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
