"""Application configuration — environment-driven, no secrets in code."""
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "ResilientAI"
    VERSION: str = "0.1.0"
    DEBUG: bool = False

    # Database — defaults to SQLite for local dev, postgres in production
    DATABASE_URL: str = "sqlite+aiosqlite:///./resilientai_dev.db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379"

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]

    # LLM Gateway — Claude primary, Grok fallback
    ANTHROPIC_API_KEY: str = ""
    GROQ_API_KEY: str = ""
    LLM_PRIMARY: str = "claude-sonnet-4-6"
    LLM_FALLBACK: str = "llama3-70b-8192"

    # Existing Tinlance infrastructure bridges
    THREATFADE_URL: str = "http://13.50.16.19:8000"
    FUSIONOPS_URL: str = "http://13.50.16.19:8001"
    RECONOS_URL: str = ""
    BUGFLOW_URL: str = ""
    BRIDGE_TIMEOUT: int = 10

    # Billing
    LEMONSQUEEZY_API_KEY: str = ""
    LEMONSQUEEZY_STORE_ID: str = "247127"
    LEMONSQUEEZY_WEBHOOK_SECRET: str = ""
    LS_STARTER_VARIANT_ID: str = ""
    LS_BUSINESS_VARIANT_ID: str = ""
    LS_ENTERPRISE_VARIANT_ID: str = ""
    LS_CHECKOUT_BASE_URL: str = "https://resilientai.lemonsqueezy.com/checkout"

    # Auth
    CLERK_SECRET_KEY: str = ""
    CLERK_PUBLISHABLE_KEY: str = ""

    # Resend email
    RESEND_API_KEY: str = ""
    EMAIL_FROM: str = "noreply@resilientai.tinlance.com"

    # Resilience scoring
    RESILIENCE_WARN_THRESHOLD: int = 60
    RESILIENCE_CRITICAL_THRESHOLD: int = 40
    PREDICTION_HORIZON_HOURS: int = 72


    # ── Ecosystem Bridge URLs ─────────────────────────────────────────
    # Set these as each product deploys — bridges activate automatically
    RECONOS_URL: str = ""
    BUGFLOW_URL: str = ""
    FDSE_URL: str = ""
    HEZCAST_URL: str = ""
    TWINGUARD_URL: str = ""
    FADEFORGE_URL: str = ""
    FADEFORGE_API_KEY: str = ""
    AI_SHIELD_URL: str = "http://13.50.16.19:8002"
    KALEVIO_URL: str = ""
    KALEVIO_API_KEY: str = ""
    OLVRIX_URL: str = ""
    OLVRIX_BRIDGE_KEY: str = ""
    FADEREACH_URL: str = ""
    FADEREACH_API_KEY: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
