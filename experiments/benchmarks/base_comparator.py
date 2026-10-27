from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvaluationResult:
    """Individual payload evaluation result produced by a defense comparator."""

    comparator_name: str
    payload: str
    is_attack_ground_truth: bool
    blocked: bool
    latency_ms: float
    is_true_positive: bool
    is_false_positive: bool
    is_true_negative: bool
    is_false_negative: bool
    details: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseComparator(ABC):
    """Abstract interface for security baseline comparators."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the defense baseline comparator."""

    @abstractmethod
    def evaluate(
        self,
        payload: str,
        is_attack: bool,
        metadata: dict[str, Any] | None = None,
    ) -> EvaluationResult:
        """Evaluate a single payload and return classification and latency metrics."""
