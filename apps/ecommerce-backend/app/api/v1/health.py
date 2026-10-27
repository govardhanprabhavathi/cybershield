from datetime import UTC, datetime

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from app import __version__
from app.core.config import get_settings
from app.core.database import check_db_health
from app.core.redis import check_redis_health

router = APIRouter()
settings = get_settings()


class ServiceHealthResponse(BaseModel):
    status: str = Field(examples=["healthy"])
    service: str = Field(examples=["cybershield-ecommerce-backend"])
    version: str = Field(examples=["0.1.0"])
    environment: str = Field(examples=["development"])
    timestamp: str


class ReadinessCheckResponse(BaseModel):
    status: str = Field(examples=["ready"])
    database: dict
    redis: dict
    timestamp: str


@router.get(
    "",
    response_model=ServiceHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Application Liveness Check",
)
async def health_check():
    """Verify application process liveness and general configuration status."""
    return ServiceHealthResponse(
        status="healthy",
        service=settings.PROJECT_NAME,
        version=__version__,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(UTC).isoformat(),
    )


@router.get(
    "/ready",
    response_model=ReadinessCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Application Readiness Probe",
)
async def readiness_check():
    """Verify live connectivity to critical downstream state backends (Database & Redis)."""
    db_health = await check_db_health()
    redis_health = await check_redis_health()

    is_ready = db_health.get("status") == "ok" and redis_health.get("status") in ("ok", "degraded")

    return ReadinessCheckResponse(
        status="ready" if is_ready else "not_ready",
        database=db_health,
        redis=redis_health,
        timestamp=datetime.now(UTC).isoformat(),
    )
