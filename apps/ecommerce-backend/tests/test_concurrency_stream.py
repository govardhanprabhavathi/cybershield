"""Test suite for Phase 7: Multi-attack concurrency, stream processing worker pool, and LSPR preservation."""

import pytest
from httpx import AsyncClient

from agents.session_security.session_agent import SessionSecurityAgent
from services.runtime_security.worker_pool import DetectionWorkerPool
from simulators.attack_simulator.attack_simulator import AttackSimulator
from simulators.concurrency_harness import ConcurrencyBenchmarkHarness
from simulators.legitimate_user.user_simulator import LegitimateUserSimulator


@pytest.mark.asyncio
async def test_legitimate_user_simulator_shopping_journey(async_client: AsyncClient):
    simulator = LegitimateUserSimulator(
        client=async_client,
        email="benign_shopper_1@cybershield.io",
        client_ip="192.168.1.100",
    )
    result = await simulator.run_shopping_journey()

    assert result.is_preserved is True
    assert result.failed_requests == 0
    assert result.successful_requests >= 5
    assert result.success_rate == 1.0

    # Verify session risk baseline remained ALLOW with 0 risk score (Zero False Positives)
    agent = SessionSecurityAgent()
    profile = await agent.get_profile(simulator.session_id)
    assert profile.risk_score == 0
    assert profile.state == "ALLOW"


@pytest.mark.asyncio
async def test_attack_simulator_multi_vector_escalation(async_client: AsyncClient):
    attacker = AttackSimulator(
        client=async_client,
        persona="MULTI_VECTOR",
        email="adversary_multi_1@cybershield.io",
        client_ip="198.51.100.99",
    )
    result = await attacker.execute()
    assert result.total_probes >= 5

    # Drain worker pool to digest attack telemetry
    pool = DetectionWorkerPool(concurrency=2)
    await pool.drain_all(max_cycles=5, count_per_worker=50)

    # Verify session risk escalated to CONTAIN
    agent = SessionSecurityAgent()
    profile = await agent.get_profile(attacker.session_id)
    assert profile.state == "CONTAIN"
    assert profile.risk_score >= 90

    # Verify subsequent authenticated request is blocked with HTTP 403
    blocked = await attacker._send_probe("GET", "/api/v1/auth/me")
    assert blocked.status_code == 403


@pytest.mark.asyncio
async def test_concurrent_worker_pool_stream_balancing(async_client: AsyncClient):
    pool = DetectionWorkerPool(concurrency=3)

    # Generate some traffic to ensure events are buffered
    await async_client.get("/api/v1/products")
    await async_client.get("/api/v1/products?search=shoes")

    incidents = await pool.drain_all(max_cycles=3, count_per_worker=50)
    assert isinstance(incidents, list)

    stats = await pool.get_stats()
    assert stats["concurrency"] == 3
    assert len(stats["worker_names"]) == 3
    assert "stream_stats" in stats


@pytest.mark.asyncio
async def test_shared_ip_disambiguation(async_client: AsyncClient):
    """Core University Evaluation: Disambiguates attacker from legitimate user on the SAME IP."""
    shared_gateway_ip = "198.51.100.1"

    # 1. Start legitimate user from shared IP
    shopper = LegitimateUserSimulator(
        client=async_client,
        email="shared_shopper@cybershield.io",
        client_ip=shared_gateway_ip,
    )
    await shopper.register_and_login()
    await shopper.browse_catalog()

    # 2. Start malicious attacker from the EXACT SAME IP
    attacker = AttackSimulator(
        client=async_client,
        persona="MULTI_VECTOR",
        email="shared_attacker@cybershield.io",
        client_ip=shared_gateway_ip,
    )
    await attacker.execute()

    # 3. Drain stream processing pool
    pool = DetectionWorkerPool(concurrency=2)
    await pool.drain_all(max_cycles=5, count_per_worker=50)

    # 4. Verify attacker session is CONTAINED (HTTP 403)
    attacker_probe = await attacker._send_probe("GET", "/api/v1/auth/me")
    assert attacker_probe.status_code == 403

    # 5. Verify legitimate user on the SAME IP remains fully PRESERVED (HTTP 200)
    shopper_probe = await shopper.view_profile()
    assert shopper_probe is not None
    assert shopper_probe.status_code == 200

    # Validate independent risk profiles
    agent = SessionSecurityAgent()
    shopper_profile = await agent.get_profile(shopper.session_id)
    attacker_profile = await agent.get_profile(attacker.session_id)

    assert shopper_profile.state == "ALLOW"
    assert shopper_profile.risk_score == 0
    assert attacker_profile.state == "CONTAIN"
    assert attacker_profile.risk_score >= 90


@pytest.mark.asyncio
async def test_concurrency_benchmark_harness_execution(async_client: AsyncClient):
    harness = ConcurrencyBenchmarkHarness(
        client=async_client,
        legitimate_count=3,
        attacker_count=2,
        worker_concurrency=2,
    )
    report = await harness.run_benchmark()

    # Formal Research Acceptance Criteria
    assert report.legitimate_sessions_count == 3
    assert report.attacker_sessions_count == 2
    assert report.legitimate_session_preservation_rate >= 98.0
    assert report.attacker_containment_rate == 100.0
    assert report.false_positive_rate == 0.0


@pytest.mark.asyncio
async def test_simulation_api_endpoints(async_client: AsyncClient):
    # 1. Metrics / Criteria Endpoint
    metrics_res = await async_client.get("/security/v1/simulation/metrics")
    assert metrics_res.status_code == 200
    metrics_data = metrics_res.json()
    assert "evaluation_criteria" in metrics_data
    assert metrics_data["evaluation_criteria"]["legitimate_session_preservation_target"] == ">= 98.0%"

    # 2. Benchmark Execution Endpoint
    benchmark_res = await async_client.post(
        "/security/v1/simulation/benchmark?legitimate_count=2&attacker_count=1&worker_concurrency=2"
    )
    assert benchmark_res.status_code == 200
    bench_data = benchmark_res.json()
    assert bench_data["legitimate_sessions_count"] == 2
    assert bench_data["attacker_sessions_count"] == 1
    assert bench_data["legitimate_session_preservation_rate"] >= 98.0
    assert bench_data["attacker_containment_rate"] == 100.0
