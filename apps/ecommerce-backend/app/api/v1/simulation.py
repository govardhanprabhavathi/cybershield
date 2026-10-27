"""Concurrency and traffic simulation REST API endpoints."""

from typing import Any

from fastapi import APIRouter, Query, Request, status
from httpx import ASGITransport, AsyncClient

from simulators.concurrency_harness import ConcurrencyBenchmarkHarness, ConcurrencyBenchmarkReport
from telemetry.processors.stream_processor import TelemetryStreamProcessor

router = APIRouter()
processor = TelemetryStreamProcessor()


@router.post(
    "/simulation/benchmark",
    response_model=ConcurrencyBenchmarkReport,
    status_code=status.HTTP_200_OK,
    summary="Execute multi-source concurrent benchmark measuring LSPR and containment rates",
)
async def execute_concurrency_benchmark(
    request: Request,
    legitimate_count: int = Query(default=3, ge=1, le=20, description="Concurrent legitimate shopper sessions"),
    attacker_count: int = Query(default=2, ge=1, le=10, description="Concurrent adversary attack sessions"),
    worker_concurrency: int = Query(default=4, ge=1, le=8, description="Parallel stream consumer worker threads"),
    shared_ip: str | None = Query(default=None, description="Optional shared IP address to evaluate NAT disambiguation"),
):
    """Executes live concurrent traffic simulation across parallel legitimate users and multi-vector attacker bots."""
    transport = ASGITransport(app=request.app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        harness = ConcurrencyBenchmarkHarness(
            client=client,
            legitimate_count=legitimate_count,
            attacker_count=attacker_count,
            worker_concurrency=worker_concurrency,
            shared_ip=shared_ip,
        )
        report = await harness.run_benchmark()
        return report


@router.get(
    "/simulation/metrics",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Retrieve system concurrency targets and telemetry throughput metrics",
)
async def get_simulation_targets_and_metrics():
    """Provides formal research acceptance thresholds and active stream processor health."""
    stream_stats = await processor.get_stream_stats()
    return {
        "evaluation_criteria": {
            "legitimate_session_preservation_target": ">= 98.0%",
            "attacker_containment_target": "100.0%",
            "false_positive_rate_target": "0.0%",
            "telemetry_latency_overhead_target": "< 2.0ms",
        },
        "stream_health": stream_stats,
    }
