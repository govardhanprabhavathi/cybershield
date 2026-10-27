from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

from app.core.config import get_settings
from app.core.logging import logger

settings = get_settings()

Base = declarative_base()

_engine = None
_async_session_maker = None
_active_dialect = "uninitialized"


async def get_engine():
    """Lazily initialize and return the async database engine with dual-mode fallback."""
    global _engine, _async_session_maker, _active_dialect

    if _engine is not None:
        return _engine

    if settings.is_testing and settings.USE_SQLITE_FALLBACK:
        _engine = create_async_engine(
            settings.SQLITE_FALLBACK_URL,
            echo=False,
            connect_args={"check_same_thread": False},
        )
        _active_dialect = "sqlite"
        _async_session_maker = async_sessionmaker(
            _engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        return _engine

    target_url = settings.DATABASE_URL

    try:
        connect_args = {"timeout": 2} if "asyncpg" in target_url else {}
        engine = create_async_engine(
            target_url,
            echo=settings.DEBUG,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        _engine = engine
        _active_dialect = "postgresql"
        logger.info("Successfully connected to primary PostgreSQL database.")
    except Exception as exc:
        if settings.USE_SQLITE_FALLBACK:
            logger.warning(
                f"PostgreSQL connection failed ({exc}). Falling back to SQLite ({settings.SQLITE_FALLBACK_URL})."
            )
            fallback_engine = create_async_engine(
                settings.SQLITE_FALLBACK_URL,
                echo=False,
                connect_args={"check_same_thread": False},
            )
            async with fallback_engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            _engine = fallback_engine
            _active_dialect = "sqlite"
        else:
            logger.error(f"Failed to connect to database at {target_url}: {exc}")
            raise

    _async_session_maker = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    return _engine


async def get_session_maker():
    if _async_session_maker is None:
        await get_engine()
    return _async_session_maker


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for yielding an active async database session."""
    session_maker = await get_session_maker()
    async with session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


async def check_db_health() -> dict:
    """Perform a live ping on the database connection and report health status."""
    try:
        engine = await get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "ok", "dialect": _active_dialect}
    except (SQLAlchemyError, OSError, Exception) as exc:  # noqa: BLE001
        return {"status": "unhealthy", "error": str(exc), "dialect": _active_dialect}


async def close_db():
    """Dispose of active engine connections during app shutdown."""
    global _engine, _async_session_maker
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session_maker = None
