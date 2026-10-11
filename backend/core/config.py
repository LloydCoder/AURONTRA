"""Application configuration — environment-driven, no production endpoints or secrets in code."""
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

    APP_NAME: str = "Aurontra"
    VERSION: str = "0.1.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # Secure-by-default: the business data plane stays closed until auth and tenant-scoped persistence are ready.
    AUTH_MODE: str = "required"
    DATA_PLANE_ENABLED: bool = False
    DB_SCHEMA_REVISION: str = "0005_agent_dpop_identity"
    TEST_MODE: bool = False
    JWT_JWKS_URL: str = ""
    JWT_ISSUER: str = ""
    JWT_AUDIENCE: str = ""
    MAX_REQUEST_BODY_BYTES: int = 1048576

    # Endpoint-agent identity is verified against the Platform-approved issuer.
    # Aurontra never mints agent credentials or stores private keys.
    AGENT_AUTH_ENABLED: bool = False
    AGENT_JWKS_URL: str = ""
    AGENT_JWT_ISSUER: str = ""
    AGENT_JWT_AUDIENCE: str = ""
    AGENT_PUBLIC_ORIGIN: str = ""
    AGENT_DPOP_MAX_AGE_SECONDS: int = 60
    AGENT_CLOCK_SKEW_SECONDS: int = 30
    AGENT_ACCESS_TOKEN_MAX_TTL_SECONDS: int = 600
    AGENT_REPLAY_RETENTION_SECONDS: int = 300

    # Local development default; production must explicitly configure PostgreSQL.
    DATABASE_URL: str = "sqlite+aiosqlite:///./aurontra_dev.db"
    REDIS_URL: str = "redis://localhost:6379"

    # Only configure customer-controlled origins explicitly.
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]

    # LLM gateway credentials are optional; empty values must use offline fallback.
    ANTHROPIC_API_KEY: str = ""
    GROQ_API_KEY: str = ""
    LLM_PRIMARY: str = "claude-sonnet-4-6"
    LLM_FALLBACK: str = "llama3-70b-8192"

    # Integration endpoints are intentionally unset by default. Configure TLS
    # endpoints and service credentials per environment; never fall back to
    # hardcoded public IPs or plaintext HTTP.
    THREATFADE_URL: str = ""
    FUSIONOPS_URL: str = ""
    RECONOS_URL: str = ""
    BUGFLOW_URL: str = ""
    FDSE_URL: str = ""
    HEZCAST_URL: str = ""
    TWINGUARD_URL: str = ""
    FADEFORGE_URL: str = ""
    FADEFORGE_API_KEY: str = ""
    AI_SHIELD_URL: str = ""
    KALEVIO_URL: str = ""
    KALEVIO_API_KEY: str = ""
    OLVRIX_URL: str = ""
    OLVRIX_BRIDGE_KEY: str = ""
    FADEREACH_URL: str = ""
    FADEREACH_API_KEY: str = ""
    BRIDGE_TIMEOUT: int = 5

    # Billing provider configuration. Production webhook verification fails closed.
    LEMONSQUEEZY_API_KEY: str = ""
    LEMONSQUEEZY_STORE_ID: str = "247127"
    LEMONSQUEEZY_WEBHOOK_SECRET: str = ""
    LS_STARTER_VARIANT_ID: str = ""
    LS_BUSINESS_VARIANT_ID: str = ""
    LS_ENTERPRISE_VARIANT_ID: str = ""
    LS_CHECKOUT_BASE_URL: str = ""

    # Configure JWKS URL, issuer and audience for the selected Clerk JWT template.
    CLERK_SECRET_KEY: str = ""
    CLERK_PUBLISHABLE_KEY: str = ""

    RESEND_API_KEY: str = ""
    EMAIL_FROM: str = ""

    RESILIENCE_WARN_THRESHOLD: int = 60
    RESILIENCE_CRITICAL_THRESHOLD: int = 40
    PREDICTION_HORIZON_HOURS: int = 72


settings = Settings()
