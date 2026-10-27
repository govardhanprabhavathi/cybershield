"""High-throughput asynchronous Redis Stream publisher for security telemetry events."""

import asyncio

from app.core.logging import logger
from app.core.redis import get_redis

from telemetry.schemas.events import SecurityTelemetryEvent

DEFAULT_STREAM_NAME = "cybershield:telemetry:stream"


class TelemetryStreamPublisher:
    """Publishes security telemetry events to Redis Stream without blocking request path."""

    def __init__(self, stream_name: str = DEFAULT_STREAM_NAME):
        self.stream_name = stream_name

    async def publish(self, event: SecurityTelemetryEvent) -> str | None:
        """Publish event to Redis Stream synchronously within an async task."""
        try:
            client = await get_redis()
            payload = event.model_dump_json()
            message_id = await client.xadd(
                self.stream_name,
                {"event": payload},
                maxlen=100000,
                approximate=True,
            )
            return message_id
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"Failed to publish telemetry event {event.event_id} to Redis stream: {exc}")
            return None

    def publish_background(self, event: SecurityTelemetryEvent) -> asyncio.Task | None:
        """Fire-and-forget background task ensuring zero latency overhead on critical request path."""
        try:
            loop = asyncio.get_running_loop()
            return loop.create_task(self.publish(event))
        except RuntimeError:
            return None
