from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """CyberShield Core Application Settings and Security Configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # General
    ENVIRONMENT: str = Field(default="development", description="Current execution environment")
    DEBUG: bool = Field(default=True, description="Enable verbose debug mode")
    PROJECT_NAME: str = Field(default="CyberShield E-Commerce Defense Platform")
    API_V1_PREFIX: str = Field(default="/api/v1")
    SECURITY_V1_PREFIX: str = Field(default="/security/v1")

    # Cryptography & Token Secrets
    SECRET_KEY: str = Field(
        default="cybershield-dev-secret-key-32-chars-minimum-length-needed-1234",
        description="Core secret key for signatures",
    )
    JWT_SECRET: str = Field(
        default="super-secret-jwt-signing-key-for-cybershield-tokens-9876",
        description="HMAC secret for JWT issuance and verification",
    )
    JWT_ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7)

    # Database
    POSTGRES_USER: str = Field(default="cybershield_user")
    POSTGRES_PASSWORD: str = Field(default="cybershield_pass")
    POSTGRES_DB: str = Field(default="cybershield_db")
    POSTGRES_HOST: str = Field(default="localhost")
    POSTGRES_PORT: int = Field(default=5432)
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://cybershield_user:cybershield_pass@localhost:5432/cybershield_db"
    )
    SQLITE_FALLBACK_URL: str = Field(
        default="sqlite+aiosqlite:///./cybershield_dev.db",
        description="Local fallback database connection when PostgreSQL is unavailable",
    )
    USE_SQLITE_FALLBACK: bool = Field(
        default=True,
        description="Gracefully fallback to SQLite if PostgreSQL connection fails",
    )

    # Redis Fast State & Streams
    REDIS_HOST: str = Field(default="localhost")
    REDIS_PORT: int = Field(default=6379)
    REDIS_PASSWORD: str | None = Field(default=None)
    REDIS_DB: int = Field(default=0)
    REDIS_STREAM_KEY: str = Field(default="events:runtime")
    REDIS_USE_FAKEREDIS_FALLBACK: bool = Field(
        default=True,
        description="Use in-memory fake Redis when standalone server is not reachable",
    )

    # Graduated Response Thresholds
    RISK_THRESHOLD_MONITOR: int = Field(default=30)
    RISK_THRESHOLD_THROTTLE: int = Field(default=50)
    RISK_THRESHOLD_CONTAIN: int = Field(default=85)
    CONFIDENCE_THRESHOLD_CONTAIN: float = Field(default=0.85)

    # AI Reasoning
    LLM_PROVIDER: str = Field(default="gemini")
    GEMINI_API_KEY: str = Field(default="mock-key-for-local-dev")
    LLM_MODEL: str = Field(default="gemini-1.5-pro")

    # Observability
    OTEL_SERVICE_NAME: str = Field(default="cybershield-ecommerce")
    OTEL_EXPORTER_OTLP_ENDPOINT: str = Field(default="http://localhost:4317")
    OTEL_ENABLED: bool = Field(default=False)

    # Controlled Vulnerability Toggles (For Research & Testing)
    VULNERABILITY_MODE: bool = Field(
        default=True,
        description="Master switch enabling controlled test vulnerabilities",
    )
    ENABLE_VULNERABILITY_SQLI: bool = Field(
        default=True,
        description="Enable raw unescaped query execution on search endpoint",
    )
    ENABLE_VULNERABILITY_BOLA: bool = Field(
        default=True,
        description="Enable IDOR/BOLA bypass on order details endpoint",
    )
    ENABLE_VULNERABILITY_BUSINESS_FLOW: bool = Field(
        default=True,
        description="Allow negative item quantities and abnormal cart price manipulation",
    )
    ENABLE_VULNERABILITY_RESOURCE_CONSUMPTION: bool = Field(
        default=True,
        description="Allow unbounded query limit pagination",
    )

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_testing(self) -> bool:
        return self.ENVIRONMENT.lower() == "test"


@lru_cache
def get_settings() -> Settings:
    """Provide cached settings instance across dependency injections."""
    return Settings()
