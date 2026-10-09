"""ResilientAI — FastAPI entry point. Complete product."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from core.database import init_db
from api.routes import (
    health, tickets, devices, resilience,
    automation, threats, billing, reports,
    onboarding, kb, sla,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"[ResilientAI] Starting {settings.APP_NAME} v{settings.VERSION}")
    await init_db()
    logger.info("[ResilientAI] Database initialised")
    yield
    logger.info("[ResilientAI] Shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Proactive IT resilience + cyber defence as a service. Powered by ThreatFade.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
