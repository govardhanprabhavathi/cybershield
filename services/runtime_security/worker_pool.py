"""Concurrent worker pool orchestrator scaling stream processing across multiple detection consumers."""

import asyncio
from typing import Any

from app.core.database import get_session_maker
from app.core.logging import logger

from security.schemas.incident import RuntimeIncident
from services.runtime_security.detection_worker import DetectionWorkerService
from telemetry.processors.stream_processor import TelemetryStreamProcessor


class DetectionWorkerPool:
    """Manages concurrent worker consumers reading from Redis Streams under a shared consumer group."""

    def __init__(
        self,
        concurrency: int = 4,
        processor: TelemetryStreamProcessor | None = None,
    ):
        self.concurrency = concurrency
        self.processor = processor or TelemetryStreamProcessor()
        self.workers: list[tuple[str, DetectionWorkerService]] = [
            (f"worker-{i + 1}", DetectionWorkerService(processor=self.processor))
            for i in range(concurrency)
        ]
        self.total_incidents_processed: int = 0
        self.total_cycles_executed: int = 0

    async def _run_single_worker(
        self,
        consumer_name: str,
        worker: DetectionWorkerService,
        count: int,
        block_ms: int,
    ) -> list[RuntimeIncident]:
        session_maker = await get_session_maker()
        async with session_maker() as session:
            try:
                incidents = await worker.process_batch(
                    db=session,
                    count=count,
                    consumer_name=consumer_name,
                    block_ms=block_ms,
                )
                return incidents
            except Exception as exc:  # noqa: BLE001
                logger.error(f"Worker {consumer_name} encountered error during batch processing: {exc}")
                return []

    async def process_cycle(
        self,
        count_per_worker: int = 50,
        block_ms: int = 100,
    ) -> list[RuntimeIncident]:
        """Execute a single concurrent processing cycle across all workers in the pool."""
        self.total_cycles_executed += 1
        tasks = [
            self._run_single_worker(name, worker, count=count_per_worker, block_ms=block_ms)
            for name, worker in self.workers
        ]

        results = await asyncio.gather(*tasks)
        all_incidents: list[RuntimeIncident] = []
        for batch in results:
            all_incidents.extend(batch)

        self.total_incidents_processed += len(all_incidents)
        return all_incidents

    async def drain_all(
        self,
        max_cycles: int = 10,
        count_per_worker: int = 50,
        block_ms: int = 50,
    ) -> list[RuntimeIncident]:
        """Iteratively execute processing cycles until the stream buffer is drained across all workers."""
        accumulated_incidents: list[RuntimeIncident] = []

        for _ in range(max_cycles):
            cycle_incidents = await self.process_cycle(
                count_per_worker=count_per_worker,
                block_ms=block_ms,
            )
            accumulated_incidents.extend(cycle_incidents)
            if not cycle_incidents:
                break

        return accumulated_incidents

    async def get_pool_stats(self) -> dict[str, Any]:
        """Query worker pool configuration and underlying Redis Stream queue metrics."""
        stream_stats = await self.processor.get_stream_stats()
        return {
            "concurrency": self.concurrency,
            "worker_names": [name for name, _ in self.workers],
            "total_cycles_executed": self.total_cycles_executed,
            "total_incidents_processed": self.total_incidents_processed,
            "stream_stats": stream_stats,
        }

    async def get_stats(self) -> dict[str, Any]:
        """Convenience alias for get_pool_stats."""
        return await self.get_pool_stats()
