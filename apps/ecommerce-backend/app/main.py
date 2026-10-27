from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.v1 import api_v1_router
from app.api.v1.correlation import router as correlation_router
from app.api.v1.experiments import router as experiments_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.orchestrator import router as orchestrator_router
from app.api.v1.remediation import router as remediation_router
from app.api.v1.security_scan import router as security_router
from app.api.v1.session_risk import router as session_risk_router
from app.api.v1.simulation import router as simulation_router
from app.api.v1.telemetry import router as telemetry_router
from app.core.config import get_settings
from app.core.database import close_db, get_engine, get_session_maker
from app.core.logging import logger, setup_logging
from app.core.redis import close_redis, get_redis
from telemetry.collectors.middleware import CyberShieldTelemetryMiddleware

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events: connection pools on startup and cleanup on shutdown."""
    setup_logging(environment=settings.ENVIRONMENT, debug=settings.DEBUG)
    logger.info(f"Starting {settings.PROJECT_NAME} v{__version__} [{settings.ENVIRONMENT}]")

    # Initialize connection pools and database schema
    try:
        engine = await get_engine()
        async with engine.begin() as conn:
            import app.models  # noqa: F401 - ensure models are registered
            from app.core.database import Base
            await conn.run_sync(Base.metadata.create_all)

        session_maker = await get_session_maker()
        async with session_maker() as session:
            from app.seed import seed_database
            await seed_database(session)

        await get_redis()
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Error during service startup initialization: {exc}")

    yield

    # Clean shutdown
    logger.info("Shutting down CyberShield backend resources...")
    await close_db()
    await close_redis()
    logger.info("Graceful shutdown complete.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=__version__,
    description="Controlled E-Commerce application with integrated multi-agent security and runtime telemetry.",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# CORS Middleware (configured for local dev + storefront origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# CyberShield Live Runtime Telemetry Middleware
app.add_middleware(CyberShieldTelemetryMiddleware)


@app.get("/", include_in_schema=False)
async def root():
    return JSONResponse(
        {
            "name": settings.PROJECT_NAME,
            "version": __version__,
            "status": "online",
            "docs": "/docs" if settings.DEBUG else "disabled in production",
        }
    )


# Mount versioned routers
app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)
app.include_router(security_router, prefix=settings.SECURITY_V1_PREFIX, tags=["Pre-Deployment Security"])
app.include_router(incidents_router, prefix=settings.SECURITY_V1_PREFIX, tags=["Runtime Incident Management"])
app.include_router(session_risk_router, prefix=settings.SECURITY_V1_PREFIX, tags=["Session Security & Risk Engine"])
app.include_router(simulation_router, prefix=settings.SECURITY_V1_PREFIX, tags=["Concurrency & Attack Simulation"])
app.include_router(correlation_router, prefix=settings.SECURITY_V1_PREFIX, tags=["Evidence Correlation & Triangulation"])
app.include_router(remediation_router, prefix=settings.SECURITY_V1_PREFIX, tags=["Automated Remediation & Verification"])
app.include_router(orchestrator_router, prefix="", tags=["AI Security Orchestrator"])
app.include_router(experiments_router, prefix=settings.SECURITY_V1_PREFIX, tags=["Quantitative Research Evaluation"])
app.include_router(telemetry_router, prefix="/telemetry/v1", tags=["Runtime Telemetry"])

