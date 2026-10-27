from __future__ import annotations

import time
from typing import Any

from experiments.benchmarks.base_comparator import BaseComparator, EvaluationResult


class VanillaUnprotectedComparator(BaseComparator):
    """Baseline A: Vanilla unprotected application with zero inline security inspection."""

    @property
    def name(self) -> str:
        return "Vanilla Unprotected"

    def evaluate(
        self,
        payload: str,
        is_attack: bool,
        metadata: dict[str, Any] | None = None,
    ) -> EvaluationResult:
        t0 = time.perf_counter()
        # Simulated baseline request handling without security filters
        _ = payload.strip()
        latency = (time.perf_counter() - t0) * 1000.0 + 0.15  # Nominal baseline overhead

        blocked = False
        return EvaluationResult(
            comparator_name=self.name,
            payload=payload,
            is_attack_ground_truth=is_attack,
            blocked=blocked,
            latency_ms=latency,
            is_true_positive=False,
            is_false_positive=False,
            is_true_negative=not is_attack,
            is_false_negative=is_attack,
            details="Vanilla passthrough: no inspection performed",
        )
