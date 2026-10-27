from __future__ import annotations

import statistics
import time
from pathlib import Path
from typing import Any, ClassVar

from security.remediation_engine.ast_patcher import ASTPatchGenerator
from security.remediation_engine.sandbox import RemediationSandbox


class AutomatedRemediationExperiment:
    """Experiment 4 (RQ4): Evaluates AST patch generation latency, sandbox validation, and regression rates."""

    EVALUATION_TARGETS: ClassVar[list[dict[str, Any]]] = [
        {
            "cwe_id": "CWE-89",
            "name": "SQL Injection in Product Search",
            "file_path": "apps/ecommerce-backend/app/services/product_service.py",
            "fallback_snippet": '''"""Product catalog service with toggle-controlled SQLi flaw."""
from sqlalchemy import text
from fastapi import HTTPException, status
from app.models.product import Product

async def search_products(db, filters, limit: int = 50):
    if filters.search and settings.ENABLE_VULNERABILITY_SQLI:
        raw_sql = f"SELECT id, name, slug, description, category, price, stock, is_active, created_at, updated_at FROM products WHERE is_active = 1 AND (name LIKE '%{filters.search}%' OR description LIKE '%{filters.search}%') LIMIT {limit} OFFSET {filters.offset}"
        try:
            result = await db.execute(text(raw_sql))
            rows = result.mappings().all()
            products = []
            for row in rows:
                products.append(Product(**row))
            return products
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database execution error: {exc}",
            ) from exc
    return []
''',
        },
        {
            "cwe_id": "CWE-284",
            "name": "Broken Object Level Authorization (BOLA)",
            "file_path": "apps/ecommerce-backend/app/services/order_service.py",
            "fallback_snippet": '''"""Order processing service with BOLA flaw."""
from fastapi import HTTPException, status

async def get_order_by_id(db, order_id: str, current_user):
    order = await lookup_order(db, order_id)
    if (
        not settings.ENABLE_VULNERABILITY_BOLA
        and order.user_id != current_user.id
        and current_user.role != "admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have permission to access this order",
        )
    return order
''',
        },
        {
            "cwe_id": "CWE-840",
            "name": "Business Logic Anomaly (Negative Cart Quantity)",
            "file_path": "apps/ecommerce-backend/app/services/cart_service.py",
            "fallback_snippet": '''"""Shopping cart service with business flow quantity abuse."""
from fastapi import HTTPException, status

async def add_cart_item(cart, item_in):
    if not settings.ENABLE_VULNERABILITY_BUSINESS_FLOW and item_in.quantity <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Item quantity must be a positive integer greater than zero",
        )
    cart.items.append(item_in)
    return cart
''',
        },
        {
            "cwe_id": "CWE-798",
            "name": "Hardcoded Cryptographic Secret",
            "file_path": "apps/ecommerce-backend/app/core/config.py",
            "fallback_snippet": '''"""Application security configuration."""
import os

class SecurityConfig:
    SECRET_KEY: str = default="cybershield-dev-secret-key-32-chars-minimum-length-needed-1234"
    ALGORITHM: str = "HS256"
''',
        },
    ]

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = repo_root or Path.cwd()

    def _resolve_target_content(self, target: dict[str, Any]) -> tuple[str, str]:
        """Resolves target file path and source content from disk or canonical fallback."""
        rel_path = target["file_path"]
        candidate = self.repo_root / rel_path
        if candidate.is_file():
            return str(candidate), candidate.read_text(encoding="utf-8")
        return rel_path, target["fallback_snippet"]

    def run(self, iterations_per_target: int = 5) -> dict[str, Any]:
        """Execute automated remediation benchmark evaluating AST diffs and sandbox verification."""
        target_results: list[dict[str, Any]] = []

        all_gen_times: list[float] = []
        all_verify_times: list[float] = []
        all_cycle_times: list[float] = []

        for target in self.EVALUATION_TARGETS:
            cwe_id = target["cwe_id"]
            file_path, content = self._resolve_target_content(target)

            gen_times: list[float] = []
            verify_times: list[float] = []
            cycle_times: list[float] = []
            last_diff = None
            last_checks = []
            sandbox_passed = False

            for _ in range(iterations_per_target):
                # 1. Measure AST Patch Generation
                t0 = time.perf_counter()
                diff = ASTPatchGenerator.generate_patch(file_path, cwe_id, original_content=content)
                t_gen = (time.perf_counter() - t0) * 1000.0

                # 2. Measure Isolated Sandbox Validation
                t1 = time.perf_counter()
                passed, checks, _ = RemediationSandbox.run_sandbox_checks(
                    diff=diff,
                    original_full_content=content,
                )
                t_verify = (time.perf_counter() - t1) * 1000.0

                t_total = t_gen + t_verify

                gen_times.append(t_gen)
                verify_times.append(t_verify)
                cycle_times.append(t_total)

                last_diff = diff
                last_checks = checks
                sandbox_passed = passed

            all_gen_times.extend(gen_times)
            all_verify_times.extend(verify_times)
            all_cycle_times.extend(cycle_times)

            # Compute diff stats
            diff_lines = (last_diff.unified_diff if last_diff else "").splitlines()
            additions = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
            deletions = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))

            # Check individual verification components
            syntax_valid = any(c.check_name == "AST_SYNTAX_VALIDATION" and c.passed for c in last_checks)
            safety_valid = any(c.check_name == "AST_SAFETY_INSPECTION" and c.passed for c in last_checks)
            non_regr_valid = any(c.check_name == "NON_REGRESSION_INTEGRITY" and c.passed for c in last_checks)

            target_results.append({
                "cwe_id": cwe_id,
                "name": target["name"],
                "file_path": file_path,
                "strategy": last_diff.strategy if last_diff else "UNKNOWN",
                "mean_generation_ms": round(statistics.mean(gen_times), 2),
                "mean_sandbox_ms": round(statistics.mean(verify_times), 2),
                "mean_cycle_ms": round(statistics.mean(cycle_times), 2),
                "syntax_valid": syntax_valid,
                "safety_verified": safety_valid,
                "zero_regression": non_regr_valid,
                "sandbox_all_passed": sandbox_passed,
                "diff_additions": additions,
                "diff_deletions": deletions,
                "checks": [{"name": c.check_name, "passed": c.passed, "detail": c.detail} for c in last_checks],
            })

        total_tested = len(target_results)
        syntax_valid_count = sum(1 for t in target_results if t["syntax_valid"])
        exploit_neutralized_count = sum(1 for t in target_results if t["safety_verified"])
        zero_regr_count = sum(1 for t in target_results if t["zero_regression"])

        syntax_validity_rate = (syntax_valid_count / total_tested * 100.0) if total_tested > 0 else 0.0
        neutralization_rate = (exploit_neutralized_count / total_tested * 100.0) if total_tested > 0 else 0.0
        regression_rate = ((total_tested - zero_regr_count) / total_tested * 100.0) if total_tested > 0 else 0.0

        return {
            "experiment_id": "EXP-4-REMEDIATION",
            "title": "RQ4: Automated AST Remediation Cycle Time & Zero-Regression Rate",
            "total_weaknesses_evaluated": total_tested,
            "metrics": {
                "syntax_validity_rate": round(syntax_validity_rate, 2),
                "exploit_neutralization_rate": round(neutralization_rate, 2),
                "regression_rate": round(regression_rate, 2),
                "mean_patch_generation_ms": round(statistics.mean(all_gen_times), 2),
                "mean_sandbox_validation_ms": round(statistics.mean(all_verify_times), 2),
                "mean_end_to_end_cycle_ms": round(statistics.mean(all_cycle_times), 2),
                "zero_regression_achieved": (regression_rate == 0.0),
                "full_neutralization_achieved": (neutralization_rate == 100.0),
            },
            "evaluations": target_results,
        }
