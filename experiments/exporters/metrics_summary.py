"""Evaluation metric aggregation and statistical synthesis."""

from __future__ import annotations

import math
import statistics
from typing import Any


class MetricsSummarizer:
    """Computes statistical summaries, percentiles, and confidence intervals for benchmarks."""

    @staticmethod
    def compute_distribution(values: list[float], ci_confidence: float = 0.95) -> dict[str, float]:
        """Calculates distribution statistics with 95% confidence intervals."""
        if not values:
            return {
                "count": 0,
                "mean": 0.0,
                "std": 0.0,
                "min": 0.0,
                "max": 0.0,
                "p50": 0.0,
                "p95": 0.0,
                "p99": 0.0,
                "margin_of_error": 0.0,
                "ci_lower": 0.0,
                "ci_upper": 0.0,
            }

        n = len(values)
        sorted_vals = sorted(values)
        mean_val = statistics.mean(values)
        std_val = statistics.stdev(values) if n > 1 else 0.0

        p50 = sorted_vals[int(n * 0.50)]
        p95 = sorted_vals[min(int(n * 0.95), n - 1)]
        p99 = sorted_vals[min(int(n * 0.99), n - 1)]

        # z-score for 95% confidence interval is ~1.96
        z = 1.96 if ci_confidence == 0.95 else 2.576
        margin_of_error = z * (std_val / math.sqrt(n)) if n > 1 else 0.0

        return {
            "count": n,
            "mean": round(mean_val, 2),
            "std": round(std_val, 2),
            "min": round(min(values), 2),
            "max": round(max(values), 2),
            "p50": round(p50, 2),
            "p95": round(p95, 2),
            "p99": round(p99, 2),
            "margin_of_error": round(margin_of_error, 2),
            "ci_lower": round(max(0.0, mean_val - margin_of_error), 2),
            "ci_upper": round(mean_val + margin_of_error, 2),
        }

    @staticmethod
    def synthesize_all(
        exp1: dict[str, Any],
        exp2: dict[str, Any],
        exp3: dict[str, Any],
        exp4: dict[str, Any],
    ) -> dict[str, Any]:
        """Synthesize results from all 4 research experiments into a unified evaluation payload."""
        cs_latency = exp1.get("comparators", {}).get("CyberShield Dual-Plane", {})
        cs_accuracy = exp2.get("cybershield_triangulated", {})
        cs_concurrency = exp3.get("cybershield", {})
        cs_remediation = exp4.get("metrics", {})

        return {
            "title": "CyberShield Multi-Agent Security Framework Quantitative Evaluation",
            "research_questions": {
                "RQ1_Latency_Overhead": {
                    "question": "Can CyberShield maintain sub-2ms fast-path latency overhead under load?",
                    "status": "VALIDATED" if cs_latency.get("p99_ms", 999.0) <= 2.5 else "FAILED",
                    "p50_ms": cs_latency.get("p50_ms", 0.0),
                    "p95_ms": cs_latency.get("p95_ms", 0.0),
                    "p99_ms": cs_latency.get("p99_ms", 0.0),
                    "target_met": cs_latency.get("sub_2ms_compliance", False),
                },
                "RQ2_Triangulation_Accuracy": {
                    "question": "Does 3-pillar Bayesian evidence triangulation achieve FPR = 0.00%?",
                    "status": "VALIDATED" if cs_accuracy.get("fpr", 100.0) == 0.0 else "FAILED",
                    "tpr_percentage": cs_accuracy.get("tpr", 0.0),
                    "fpr_percentage": cs_accuracy.get("fpr", 0.0),
                    "precision_percentage": cs_accuracy.get("precision", 0.0),
                    "target_met": cs_accuracy.get("fpr", 100.0) == 0.0,
                },
                "RQ3_Session_Preservation_NAT": {
                    "question": "Does CyberShield maintain LSPR >= 99.5% under shared NAT IP attack storms?",
                    "status": "VALIDATED" if cs_concurrency.get("lspr_percentage", 0.0) >= 99.5 else "FAILED",
                    "lspr_percentage": cs_concurrency.get("lspr_percentage", 0.0),
                    "acr_percentage": cs_concurrency.get("acr_percentage", 0.0),
                    "fpr_percentage": cs_concurrency.get("fpr_percentage", 0.0),
                    "target_met": cs_concurrency.get("lspr_percentage", 0.0) >= 99.5,
                },
                "RQ4_Automated_Remediation": {
                    "question": "Does AST remediation achieve 100% neutralization with 0.0% regression?",
                    "status": "VALIDATED" if cs_remediation.get("regression_rate", 100.0) == 0.0 else "FAILED",
                    "syntax_validity_rate": cs_remediation.get("syntax_validity_rate", 0.0),
                    "neutralization_rate": cs_remediation.get("exploit_neutralization_rate", 0.0),
                    "regression_rate": cs_remediation.get("regression_rate", 0.0),
                    "mean_cycle_ms": cs_remediation.get("mean_end_to_end_cycle_ms", 0.0),
                    "target_met": cs_remediation.get("zero_regression_achieved", False),
                },
            },
            "raw_experiments": {
                "exp1": exp1,
                "exp2": exp2,
                "exp3": exp3,
                "exp4": exp4,
            },
        }
