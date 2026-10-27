from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any


class CorpusLoader:
    """Loads, samples, and manages the ground-truth benchmark evaluation dataset."""

    DATASET_PATH = Path(__file__).parent / "ground_truth_payloads.json"

    def __init__(self, dataset_path: Path | None = None):
        self.path = dataset_path or self.DATASET_PATH
        self._data: dict[str, Any] | None = None

    def load_corpus(self) -> dict[str, Any]:
        """Load and cache the raw JSON evaluation dataset."""
        if self._data is None:
            if not self.path.is_file():
                raise FileNotFoundError(f"Evaluation corpus dataset not found at: {self.path}")
            self._data = json.loads(self.path.read_text(encoding="utf-8"))
        return self._data

    def get_benign_queries(self, limit: int | None = None) -> list[str]:
        """Retrieve list of benign e-commerce consumer search and browsing queries."""
        data = self.load_corpus()
        queries = list(data.get("benign_queries", []))
        if limit is not None:
            return queries[:limit]
        return queries

    def get_attack_payloads(
        self,
        category: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve structured attack payloads, optionally filtered by category (SQLI, BOLA, etc.)."""
        data = self.load_corpus()
        attacks = list(data.get("attack_payloads", []))
        if category:
            attacks = [a for a in attacks if a.get("category") == category.upper()]
        if limit is not None:
            return attacks[:limit]
        return attacks

    def get_mixed_evaluation_batch(
        self,
        benign_count: int = 50,
        attack_count: int = 20,
        seed: int = 42,
    ) -> list[dict[str, Any]]:
        """Produce reproducible mixed evaluation batch with ground-truth boolean tags."""
        rng = random.Random(seed)
        benign = self.get_benign_queries()
        attacks = self.get_attack_payloads()

        # Sample with replacement if count exceeds pool
        sample_benign = [rng.choice(benign) for _ in range(benign_count)]
        sample_attacks = [rng.choice(attacks) for _ in range(attack_count)]

        batch: list[dict[str, Any]] = []
        for q in sample_benign:
            batch.append({
                "payload": q,
                "is_attack": False,
                "category": "BENIGN",
                "cwe": "NONE",
            })
        for a in sample_attacks:
            batch.append({
                "payload": a["payload"],
                "is_attack": True,
                "category": a["category"],
                "cwe": a.get("cwe", "UNKNOWN"),
            })

        rng.shuffle(batch)
        return batch
