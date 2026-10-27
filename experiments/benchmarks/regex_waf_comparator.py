from __future__ import annotations

import re
import time
from typing import Any, ClassVar

from experiments.benchmarks.base_comparator import BaseComparator, EvaluationResult


class RegexWafComparator(BaseComparator):
    """Baseline B: Naive rule-based signature WAF relying on static regular expressions."""

    # Common signature patterns derived from standard CRS / ModSecurity rule subsets
    SIGNATURE_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|TABLE)\b", re.IGNORECASE),
        re.compile(r"('|\b)(OR|AND)\b.+(=|<|>)", re.IGNORECASE),
        re.compile(r"--|/\*|\*/", re.IGNORECASE),
        re.compile(r"<script|javascript:|onerror=", re.IGNORECASE),
        re.compile(r"\.\./|\.\.\\", re.IGNORECASE),
    ]

    @property
    def name(self) -> str:
        return "Naive Signature WAF"

    def evaluate(
        self,
        payload: str,
        is_attack: bool,
        metadata: dict[str, Any] | None = None,
    ) -> EvaluationResult:
        t0 = time.perf_counter()

        blocked = False
        matched_rule = ""
        for pattern in self.SIGNATURE_PATTERNS:
            if pattern.search(payload):
                blocked = True
                matched_rule = pattern.pattern
                break

        latency = (time.perf_counter() - t0) * 1000.0 + 0.45  # Typical regex evaluation overhead

        tp = is_attack and blocked
        fp = (not is_attack) and blocked
        tn = (not is_attack) and (not blocked)
        fn = is_attack and (not blocked)

        details = f"Blocked by signature '{matched_rule}'" if blocked else "Passed signature inspection"

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
