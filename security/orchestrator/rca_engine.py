from __future__ import annotations

import logging
from typing import Any, ClassVar

from security.schemas.orchestrator import IncidentRCA

logger = logging.getLogger(__name__)


class RootCauseAnalyzer:
    """Produces structured Root Cause Analysis (RCA) and blast radius assessments."""

    CWE_METADATA: ClassVar[dict[str, dict[str, Any]]] = {
        "CWE-89": {
            "title": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "summary": "Dynamic SQL query constructed via unescaped string interpolation, enabling adversary SQL control.",
            "blast_radius": "Critical: Complete database exfiltration, unauthorized record modification, data breach.",
            "preventive": [
                "Enforce SQLAlchemy parameterized query bindings (`:parameter`) across all dynamic query paths.",
                "Disallow direct raw string concatenation in `cursor.execute` or `text()` invocations.",
                "Integrate AST pre-commit validation to catch `ast.JoinedStr` inside query strings.",
            ],
        },
        "CWE-284": {
            "title": "Improper Access Control (Broken Object Level Authorization / BOLA)",
            "summary": "Endpoint exposes object lookup by ID without asserting ownership against authenticated user session.",
            "blast_radius": "High: Horizontal privilege escalation, cross-tenant customer data disclosure.",
            "preventive": [
                "Always append `user_id == current_user.id` or `tenant_id == current_user.tenant_id` to WHERE clauses.",
                "Enforce centralized RBAC dependencies on all object lookup routes.",
                "Conduct automated DAST cross-tenant fuzzer sweeps on staging builds.",
            ],
        },
        "CWE-840": {
            "title": "Business Logic Errors (Negative Quantity Ledger Abuse)",
            "summary": "Shopping cart update accepts unvalidated negative integer quantities, inducing negative checkout balance.",
            "blast_radius": "High: Financial loss, fraudulent order credit generation, inventory depletion.",
            "preventive": [
                "Enforce Pydantic `Field(..., gt=0)` positive value assertions on all quantity models.",
                "Implement double-entry server-side inventory verification before checkout capture.",
                "Apply strict domain-driven business rules rejecting zero or negative ledger mutations.",
            ],
        },
        "CWE-798": {
            "title": "Use of Hard-coded Credentials",
            "summary": "Application relies on static string constant fallback for administrative token verification.",
            "blast_radius": "Critical: Total administrative takeover, privilege escalation, bypass of MFA.",
            "preventive": [
                "Mandate environment secret injection via secure secrets manager (HashiCorp Vault, AWS Secrets Manager).",
                "Employ pre-commit entropy scanners (Gitleaks / Agent 5) to block hardcoded strings.",
                "Use `hmac.compare_digest` for timing-resistant token verification.",
            ],
        },
    }

    @classmethod
    def generate_rca(
        cls,
        cwe_id: str,
        normalized_route: str,
        attack_payload: str | None = None,
        vulnerable_file: str | None = None,
        vulnerable_line: int | None = None,
        extra_details: dict[str, Any] | None = None,
    ) -> IncidentRCA:
        """Synthesize vulnerability context into structured IncidentRCA."""
        meta = cls.CWE_METADATA.get(
            cwe_id,
            {
                "title": f"Vulnerability {cwe_id}",
                "summary": f"Security flaw detected at route {normalized_route}.",
                "blast_radius": "Moderate: Potential unauthorized data access or application disruption.",
                "preventive": ["Apply defense-in-depth principles and comprehensive input validation."],
            },
        )

        details = [
            f"Vulnerability Type: {meta['title']} ({cwe_id})",
            f"Target Endpoint: {normalized_route}",
        ]
        if vulnerable_file:
            details.append(f"Vulnerable Source File: {vulnerable_file}" + (f":{vulnerable_line}" if vulnerable_line else ""))
        if attack_payload:
            details.append(f"Observed Exploit Vector: {attack_payload}")
        if extra_details:
            for k, v in extra_details.items():
                details.append(f"{k}: {v}")

        return IncidentRCA(
            cwe_id=cwe_id,
            cwe_title=meta["title"],
            root_cause_summary=meta["summary"],
            vulnerable_file=vulnerable_file,
            vulnerable_line=vulnerable_line,
            attack_vector=attack_payload or f"Observed exploit traffic on {normalized_route}",
            blast_radius=meta["blast_radius"],
            technical_details="\n".join(details),
            preventive_recommendations=meta["preventive"],
        )
