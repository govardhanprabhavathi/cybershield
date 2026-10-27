"""Telemetry inspection and stream metrics API endpoints."""

from typing import Any

from fastapi import APIRouter, Query, status

from app.core.redis import get_redis
from telemetry.exporters.stream_publisher import DEFAULT_STREAM_NAME
from telemetry.processors.stream_processor import TelemetryStreamProcessor
from telemetry.schemas.events import SecurityTelemetryEvent

router = APIRouter()
processor = TelemetryStreamProcessor()


@router.get(
    "/stats",
    status_code=status.HTTP_200_OK,
    summary="Query Redis Stream telemetry pipeline metrics",
)
async def get_telemetry_stats() -> dict[str, Any]:
    """Returns telemetry stream queue size, active consumer groups, and pending events."""
    return await processor.get_stream_stats()


@router.get(
    "/events/recent",
    status_code=status.HTTP_200_OK,
    summary="Retrieve recent telemetry events from stream buffer",
)
async def get_recent_telemetry_events(
    limit: int = Query(default=10, ge=1, le=100),
) -> list[dict[str, Any]]:
    """Fetches the most recent raw security events stored in the stream buffer."""
    client = await get_redis()
    entries = await client.xrevrange(DEFAULT_STREAM_NAME, count=limit)
    events = []
    for msg_id, fields in entries:
        if "event" in fields:
            try:
                ev = SecurityTelemetryEvent.model_validate_json(fields["event"])
                events.append({"message_id": msg_id, "event": ev.model_dump()})
            except Exception:  # noqa: BLE001
                events.append({"message_id": msg_id, "raw": fields["event"]})
    return events
