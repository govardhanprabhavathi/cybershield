from __future__ import annotations

import statistics
from typing import Any

from experiments.benchmarks.cybershield_comparator import CyberShieldComparator
from experiments.benchmarks.regex_waf_comparator import RegexWafComparator
from experiments.benchmarks.sync_llm_comparator import SyncLlmComparator
from experiments.benchmarks.vanilla_unprotected import VanillaUnprotectedComparator
from experiments.datasets.corpus_loader import CorpusLoader


class LatencyOverheadExperiment:
    """Experiment 1 (RQ1): Measures latency distribution (p50, p95, p99) across defense paradigms."""

    def __init__(self, corpus_loader: CorpusLoader | None = None):
        self.loader = corpus_loader or CorpusLoader()
        self.comparators = [
            VanillaUnprotectedComparator(),
            RegexWafComparator(),
            SyncLlmComparator(),
            CyberShieldComparator(),
        ]

    def run(self, sample_size: int = 100, seed: int = 42) -> dict[str, Any]:
        """Execute latency benchmark across ground-truth batch and aggregate statistics."""
        batch = self.loader.get_mixed_evaluation_batch(
            benign_count=int(sample_size * 0.7),
            attack_count=int(sample_size * 0.3),
            seed=seed,
        )

        results: dict[str, Any] = {
            "experiment_id": "EXP-1-LATENCY",
            "title": "RQ1: Runtime Latency Overhead & Throughput Scalability",
            "sample_size": len(batch),
            "comparators": {},
        }

        for comp in self.comparators:
            latencies: list[float] = []
            for item in batch:
                res = comp.evaluate(item["payload"], item["is_attack"])
                latencies.append(res.latency_ms)

            sorted_lat = sorted(latencies)
            p50 = sorted_lat[int(len(sorted_lat) * 0.50)]
            p95 = sorted_lat[min(int(len(sorted_lat) * 0.95), len(sorted_lat) - 1)]
            p99 = sorted_lat[min(int(len(sorted_lat) * 0.99), len(sorted_lat) - 1)]

            results["comparators"][comp.name] = {
                "mean_ms": round(statistics.mean(latencies), 2),
                "std_ms": round(statistics.stdev(latencies) if len(latencies) > 1 else 0.0, 2),
                "p50_ms": round(p50, 2),
                "p95_ms": round(p95, 2),
                "p99_ms": round(p99, 2),
                "min_ms": round(min(latencies), 2),
                "max_ms": round(max(latencies), 2),
                "sub_2ms_compliance": p99 <= 2.5,
            }

        return results
