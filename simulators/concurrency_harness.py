"""Concurrency Benchmark Harness orchestrating parallel legitimate and adversary traffic to measure LSPR and containment metrics."""

import asyncio
import time
import uuid
from typing import Any

from httpx import AsyncClient
from pydantic import BaseModel, Field

from services.runtime_security.worker_pool import DetectionWorkerPool
from simulators.attack_simulator.attack_simulator import AttackSimulator
from simulators.legitimate_user.user_simulator import LegitimateUserSimulator


class ConcurrencyBenchmarkReport(BaseModel):
    """Formal research evaluation report capturing system resilience under concurrent multi-source load."""

    total_duration_seconds: float
    legitimate_sessions_count: int
    attacker_sessions_count: int
    shared_ip_evaluated: bool

    # Core Research Metrics
    legitimate_requests_total: int
    legitimate_requests_successful: int
    legitimate_session_preservation_rate: float = Field(
        description="Percentage of legitimate requests successfully processed (Target >= 98.0%)"
    )
    attacker_sessions_contained: int
    attacker_containment_rate: float = Field(
        description="Percentage of attacker sessions successfully contained (Target 100.0%)"
    )
    false_positive_rate: float = Field(
        description="Percentage of benign sessions erroneously contained (Target 0.0%)"
    )

    # Performance & Worker Metrics
    avg_legitimate_latency_ms: float
    avg_attacker_latency_ms: float
    total_incidents_detected: int
    worker_pool_concurrency: int
    details: dict[str, Any] = Field(default_factory=dict)


class ConcurrencyBenchmarkHarness:
    """Executes controlled concurrent experiments simulating simultaneous multi-source attacks and legitimate shopping."""

    def __init__(
        self,
        client: AsyncClient,
        legitimate_count: int = 5,
        attacker_count: int = 3,
        worker_concurrency: int = 4,
        shared_ip: str | None = None,
    ):
        self.client = client
        self.legitimate_count = legitimate_count
        self.attacker_count = attacker_count
        self.worker_concurrency = worker_concurrency
        self.shared_ip = shared_ip
        self.worker_pool = DetectionWorkerPool(concurrency=worker_concurrency)

    async def run_benchmark(self) -> ConcurrencyBenchmarkReport:
        """Run concurrent multi-source benchmark trial and compute formal preservation metrics."""
        start_time = time.perf_counter()

        # 1. Instantiate Legitimate User Simulators
        legit_users: list[LegitimateUserSimulator] = []
        for i in range(self.legitimate_count):
            ip = self.shared_ip if self.shared_ip else f"192.168.10.{10 + i}"
            legit_users.append(
                LegitimateUserSimulator(
                    client=self.client,
                    email=f"legit_shopper_{i}_{uuid.uuid4().hex[:8]}@cybershield.io",
                    client_ip=ip,
                )
            )

        # 2. Instantiate Adversary Simulators with distinct attack personas
        attackers: list[AttackSimulator] = []
        personas = ["MULTI_VECTOR", "SQL_INJECTION"]
        for j in range(self.attacker_count):
            ip = self.shared_ip if self.shared_ip else f"198.51.100.{20 + j}"
            persona = personas[j % len(personas)]
            attackers.append(
                AttackSimulator(
                    client=self.client,
                    persona=persona,
                    email=f"adversary_{j}_{uuid.uuid4().hex[:8]}@cybershield.io",
                    client_ip=ip,
                )
            )

        # 3. Concurrently execute legitimate shopping journeys and attacker campaigns
        legit_tasks = [u.run_shopping_journey() for u in legit_users]
        attack_tasks = [a.execute() for a in attackers]

        # Interleave execution concurrently
        await asyncio.gather(*legit_tasks, *attack_tasks)

        # 4. Drain all telemetry from Redis Stream across concurrent worker pool
        drain_incidents = await self.worker_pool.drain_all(max_cycles=8, count_per_worker=100)

        # 5. Execute post-containment verification probes
        # A) Check that legitimate users can still access profile
        legit_preserved_count = 0
        total_legit_reqs = sum(u.result.total_requests for u in legit_users)
        success_legit_reqs = sum(u.result.successful_requests for u in legit_users)

        for u in legit_users:
            profile_res = await u.view_profile()
            if profile_res and profile_res.status_code == 200:
                legit_preserved_count += 1
                total_legit_reqs += 1
                success_legit_reqs += 1
            else:
                total_legit_reqs += 1

        # B) Check that contained attackers are actively blocked (HTTP 403)
        contained_attacker_count = 0
        for a in attackers:
            # Send an authenticated follow-up probe to verify fast-path containment
            probe_res = await a._send_probe("GET", "/api/v1/auth/me")
            if (probe_res and probe_res.status_code == 403) or a.result.is_contained:
                contained_attacker_count += 1

        duration = round(time.perf_counter() - start_time, 2)

        # 6. Compute Research Metrics
        lspr = round((success_legit_reqs / total_legit_reqs * 100.0) if total_legit_reqs > 0 else 100.0, 2)
        acr = round((contained_attacker_count / self.attacker_count * 100.0) if self.attacker_count > 0 else 100.0, 2)
        fpr = round(((self.legitimate_count - legit_preserved_count) / self.legitimate_count * 100.0) if self.legitimate_count > 0 else 0.0, 2)

        # Latency statistics
        all_legit_lats = [lat for u in legit_users for lat in u.result.latencies_ms]
        all_attk_lats = [lat for a in attackers for lat in a.result.latencies_ms]
        avg_legit_lat = round(sum(all_legit_lats) / len(all_legit_lats) if all_legit_lats else 0.0, 2)
        avg_attk_lat = round(sum(all_attk_lats) / len(all_attk_lats) if all_attk_lats else 0.0, 2)

        return ConcurrencyBenchmarkReport(
            total_duration_seconds=duration,
            legitimate_sessions_count=self.legitimate_count,
            attacker_sessions_count=self.attacker_count,
            shared_ip_evaluated=self.shared_ip is not None,
            legitimate_requests_total=total_legit_reqs,
            legitimate_requests_successful=success_legit_reqs,
            legitimate_session_preservation_rate=lspr,
            attacker_sessions_contained=contained_attacker_count,
            attacker_containment_rate=acr,
            false_positive_rate=fpr,
            avg_legitimate_latency_ms=avg_legit_lat,
            avg_attacker_latency_ms=avg_attk_lat,
            total_incidents_detected=len(drain_incidents),
            worker_pool_concurrency=self.worker_concurrency,
            details={
                "legitimate_sessions": [
                    {
                        "session_id": u.session_id,
                        "success_rate": u.result.success_rate,
                        "preserved": u.result.is_preserved,
                    }
                    for u in legit_users
                ],
                "attacker_sessions": [
                    {
                        "session_id": a.session_id,
                        "persona": a.persona,
                        "is_contained": a.result.is_contained,
                    }
                    for a in attackers
                ],
            },
        )
