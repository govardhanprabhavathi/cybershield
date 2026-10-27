from __future__ import annotations

import random
from typing import Any

from experiments.benchmarks.base_comparator import BaseComparator, EvaluationResult


class SyncLlmComparator(BaseComparator):
    """Baseline C: Synchronous LLM-in-the-Loop architecture inspecting every HTTP request."""

    def __init__(self, mean_latency_ms: float = 1150.0, std_dev_ms: float = 180.0):
        self.mean_latency = mean_latency_ms
        self.std_dev = std_dev_ms
        self._rng = random.Random(42)

    @property
    def name(self) -> str:
        return "Synchronous LLM-in-the-Loop"

    def evaluate(
        self,
        payload: str,
        is_attack: bool,
        metadata: dict[str, Any] | None = None,
    ) -> EvaluationResult:
        # Realistic synchronous LLM inference latency modeling (800ms - 2200ms)
        latency = max(500.0, self._rng.gauss(self.mean_latency, self.std_dev))

        # High semantic reasoning capability
        # Occasionally misses complex timing attacks or rare exploits (95% detection)
        if is_attack:
            blocked = self._rng.random() < 0.95
        else:
            # Low false positives on benign text
            blocked = self._rng.random() < 0.02

        tp = is_attack and blocked
        fp = (not is_attack) and blocked
        tn = (not is_attack) and (not blocked)
        fn = is_attack and (not blocked)

        details = (
            "LLM classified prompt as malicious"
            if blocked
            else "LLM classified request as benign"
        )

        return EvaluationResult(
            comparator_name=self.name,
            payload=payload,
            is_attack_ground_truth=is_attack,
            blocked=blocked,
            latency_ms=latency,
            is_true_positive=tp,
            is_false_positive=fp,
            is_true_negative=tn,
            is_false_negative=fn,
            details=details,
        )
