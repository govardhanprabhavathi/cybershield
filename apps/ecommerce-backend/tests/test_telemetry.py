"""Test suite for Phase 4: Runtime Telemetry Layer, OpenTelemetry Middleware, and Redis Stream Pipeline."""

import time

import pytest
from httpx import AsyncClient

from telemetry.exporters.stream_publisher import TelemetryStreamPublisher
from telemetry.processors.stream_processor import TelemetryStreamProcessor
from telemetry.schemas.events import SecurityIndicators, SecurityTelemetryEvent


@pytest.mark.asyncio
async def test_middleware_headers_injection(async_client: AsyncClient):
    response = await async_client.get("/api/v1/products")
    assert response.status_code == 200

    # Verify context headers injected by middleware
    assert "X-Session-ID" in response.headers
    assert "X-Request-ID" in response.headers
    assert "X-Response-Time-Ms" in response.headers

    # Unauthenticated request should generate deterministic anon session ID
    session_id = response.headers["X-Session-ID"]
    assert session_id.startswith("anon_")


@pytest.mark.asyncio
async def test_authenticated_session_tracking(async_client: AsyncClient):
    # 1. Login as Alice
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "alice@cybershield.io", "password": "AlicePass123!"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    expected_session_id = login_res.json()["session_id"]

    # 2. Make authenticated call
    res = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200

    # Verify middleware extracted session_id from JWT claims
    assert res.headers["X-Session-ID"] == expected_session_id


@pytest.mark.asyncio
async def test_redis_stream_publishing_and_consumer_batch():
    publisher = TelemetryStreamPublisher(stream_name="test:telemetry:stream")
    processor = TelemetryStreamProcessor(stream_name="test:telemetry:stream", group_name="test_group")

    event = SecurityTelemetryEvent(
        session_id="test_session_123",
        user_id="user_999",
        user_role="customer",
        client_ip="192.168.1.100",
        user_agent="CyberShield-TestAgent/1.0",
        method="GET",
        path="/api/v1/products",
        status_code=200,
        duration_ms=4.52,
        indicators=SecurityIndicators(has_sql_chars=True),
    )

    # 1. Publish event
    msg_id = await publisher.publish(event)
    assert msg_id is not None

    # 2. Consume batch via consumer group
    batch = await processor.read_batch(consumer_name="test-worker", count=10)
    assert len(batch) >= 1

    received_msg_id, received_event = batch[0]
    assert received_event.session_id == "test_session_123"
    assert received_event.user_id == "user_999"
    assert received_event.indicators.has_sql_chars is True

    # 3. Acknowledge message
    acked = await processor.ack([received_msg_id])
    assert acked >= 1


@pytest.mark.asyncio
async def test_middleware_emits_to_redis_stream_with_indicators(async_client: AsyncClient):
    # Send a request with SQL injection signature characters in query string
    sqli_url = "/api/v1/products?search=test' OR 1=1--"
    res = await async_client.get(sqli_url)
    assert res.status_code in (200, 500)

    # Inspect the recent stream events buffer endpoint
    recent_res = await async_client.get("/telemetry/v1/events/recent?limit=10")
    assert recent_res.status_code == 200
    events = recent_res.json()
    assert len(events) >= 1

    # Verify captured event has parsed SQL indicators
    matching = [
        e for e in events
        if "event" in e and e["event"]["path"] == "/api/v1/products"
    ]
    assert len(matching) >= 1
    sample = matching[0]["event"]
    assert sample["indicators"]["has_sql_chars"] is True
    assert sample["status_code"] in (200, 500)
    assert "duration_ms" in sample


@pytest.mark.asyncio
async def test_telemetry_stats_endpoint(async_client: AsyncClient):
    res = await async_client.get("/telemetry/v1/stats")
    assert res.status_code == 200
    stats = res.json()
    assert "stream_name" in stats
    assert "length" in stats
    assert stats["length"] >= 1


@pytest.mark.asyncio
async def test_telemetry_latency_overhead(async_client: AsyncClient):
    # Benchmark 15 requests to verify middleware overhead remains minimal
    durations = []
    for _ in range(15):
        t0 = time.perf_counter()
        res = await async_client.get("/api/v1/health")
        durations.append((time.perf_counter() - t0) * 1000.0)
        assert res.status_code == 200

    avg_duration = sum(durations) / len(durations)
    # Even in test suite with SQLite and fakeredis, average duration should be well under 50ms
    assert avg_duration < 50.0
