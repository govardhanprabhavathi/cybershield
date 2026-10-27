import asyncio

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from app.core.config import get_settings
from app.core.logging import logger

settings = get_settings()

_redis_client: aioredis.Redis | None = None
_is_fakeredis: bool = False


async def get_redis() -> aioredis.Redis:
    """Lazily initialize and return the async Redis client with fakeredis fallback support."""
    global _redis_client, _is_fakeredis

    if _redis_client is not None:
        return _redis_client

    if settings.is_testing and settings.REDIS_USE_FAKEREDIS_FALLBACK:
        import fakeredis.aioredis
        _redis_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        _is_fakeredis = True
        return _redis_client

    try:
        client = aioredis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD or None,
            db=settings.REDIS_DB,
            decode_responses=True,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
        )
        await asyncio.wait_for(client.ping(), timeout=1.5)
        _redis_client = client
        _is_fakeredis = False
        logger.info(f"Connected to Redis server at {settings.REDIS_HOST}:{settings.REDIS_PORT}")
    except Exception as exc:
        if settings.REDIS_USE_FAKEREDIS_FALLBACK:
            import fakeredis.aioredis
            logger.warning(
                f"Redis server connection failed ({exc}). Initializing in-memory fakeredis fallback."
            )
            _redis_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
            _is_fakeredis = True
        else:
            logger.error(f"Failed to connect to Redis at {settings.REDIS_HOST}:{settings.REDIS_PORT}: {exc}")
            raise

    return _redis_client


async def check_redis_health() -> dict:
    """Check connectivity to Redis fast-state service."""
    try:
        client = await get_redis()
        ping_res = await client.ping()
        return {
            "status": "ok" if ping_res else "degraded",
            "backend": "fakeredis" if _is_fakeredis else "standalone",
        }
    except (RedisError, OSError, Exception) as exc:  # noqa: BLE001
        return {"status": "unhealthy", "error": str(exc), "backend": "unavailable"}


async def close_redis():
    """Gracefully close Redis connections during shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
