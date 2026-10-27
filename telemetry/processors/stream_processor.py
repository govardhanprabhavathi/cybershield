"""Redis Stream consumer group processor for distributed, concurrent telemetry analysis."""

from typing import Any

from app.core.logging import logger
from app.core.redis import get_redis
from redis.exceptions import ResponseError

from telemetry.exporters.stream_publisher import DEFAULT_STREAM_NAME
from telemetry.schemas.events import SecurityTelemetryEvent

DEFAULT_GROUP_NAME = "cybershield_processors"


class TelemetryStreamProcessor:
    """Consumes and acknowledges security telemetry batches from Redis Streams via consumer groups."""

    def __init__(
        self,
        stream_name: str = DEFAULT_STREAM_NAME,
        group_name: str = DEFAULT_GROUP_NAME,
    ):
        self.stream_name = stream_name
        self.group_name = group_name

    async def initialize_group(self, id_from: str = "0") -> bool:
        """Create consumer group if it does not already exist."""
        client = await get_redis()
        try:
            await client.xgroup_create(
                name=self.stream_name,
                groupname=self.group_name,
                id=id_from,
                mkstream=True,
            )
            logger.info(f"Created consumer group '{self.group_name}' on stream '{self.stream_name}'.")
            return True
        except ResponseError as err:
            if "BUSYGROUP" in str(err):
                # Group already exists
                return True
            logger.warning(f"Error creating consumer group: {err}")
            return False

    async def read_batch(
        self,
        consumer_name: str = "worker-1",
        count: int = 50,
        block_ms: int = 500,
    ) -> list[tuple[str, SecurityTelemetryEvent]]:
        """Read a batch of pending/new telemetry events using XREADGROUP."""
        client = await get_redis()
        try:
            # Ensure group exists
            await self.initialize_group()

            streams_dict = {self.stream_name: ">"}
            raw_entries = await client.xreadgroup(
                groupname=self.group_name,
                consumername=consumer_name,
                streams=streams_dict,
                count=count,
                block=block_ms,
            )

            events: list[tuple[str, SecurityTelemetryEvent]] = []
            if not raw_entries:
                return events

            for _stream, messages in raw_entries:
                for msg_id, fields in messages:
                    if "event" in fields:
                        try:
                            event = SecurityTelemetryEvent.model_validate_json(fields["event"])
                            events.append((msg_id, event))
                        except Exception as parse_err:  # noqa: BLE001
                            logger.error(f"Failed to parse telemetry event from msg {msg_id}: {parse_err}")
            return events
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"Error reading from stream group: {exc}")
            return []

    async def ack(self, message_ids: list[str]) -> int:
        """Acknowledge processed telemetry events."""
        if not message_ids:
            return 0
        client = await get_redis()
        try:
            return await client.xack(self.stream_name, self.group_name, *message_ids)
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"Error acknowledging messages {message_ids}: {exc}")
            return 0

    async def get_stream_stats(self) -> dict[str, Any]:
        """Query stream length, consumer groups, and pending messages."""
        client = await get_redis()
        try:
            length = await client.xlen(self.stream_name)
            groups = []
            try:
                groups_info = await client.xinfo_groups(self.stream_name)
                for g in groups_info:
                    groups.append({
                        "name": g.get("name"),
                        "consumers": g.get("consumers"),
                        "pending": g.get("pending"),
                        "last_delivered_id": g.get("last-delivered-id"),
                    })
            except ResponseError as group_err:
                logger.debug(f"Consumer groups info query skipped: {group_err}")

            return {
                "stream_name": self.stream_name,
                "length": length,
                "consumer_groups": groups,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "stream_name": self.stream_name,
                "length": 0,
                "error": str(exc),
            }
