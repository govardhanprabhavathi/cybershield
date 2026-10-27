import re
from datetime import UTC, datetime
from typing import Any

from security.schemas.correlation import (
    EvidenceArtifact,
    ExploitStatus,
    PillarType,
    TriangulatedDossier,
    TriangulationTier,
)


def to_utc(dt: Any) -> datetime:
    """Ensure datetime is timezone-aware in UTC format for safe comparisons."""
    if not dt or not isinstance(dt, datetime):
        return datetime.now(UTC)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class EvidenceTriangulator:
    """Calculates multi-pillar composite confidence, normalizes routes, and synthesizes vulnerability dossiers."""

    @staticmethod
    def normalize_endpoint(path: str | None) -> str:
        """Normalize API route by stripping query params and standardizing dynamic path parameters."""
        if not path:
            return ""

        clean = path.split("?")[0].rstrip("/")

        # Standardize /orders/{order_id} (ignoring /orders/checkout and similar sub-routes)
        if re.search(r"^/api/v1/orders/(?!checkout)[^/]+$", clean):
            return "/api/v1/orders/{order_id}"

        # Standardize /products/{id}
        if re.search(r"^/api/v1/products/[a-f0-9\-]{8,}$", clean, re.IGNORECASE):
            return "/api/v1/products/{id}"

        return clean

    @staticmethod
    def calculate_composite_confidence(
        pillars: set[PillarType],
        pillar_confidences: dict[PillarType, float],
    ) -> tuple[float, TriangulationTier, ExploitStatus]:
        """Compute mathematically grounded composite confidence and assign exploit status.

        Formula: P(V) = 1.0 - Product(1.0 - c_k)
        """
        if not pillars:
            return 0.0, "SAST_ONLY", "THEORETICAL"

        # Mathematical Bayesian combination of independent evidence sources
        product_failure = 1.0
        for p in pillars:
            conf = pillar_confidences.get(p, 0.80)
            product_failure *= (1.0 - conf)

        prob = 1.0 - product_failure

        # Tier and exploit status evaluation with empirical floors
        if pillars == {"SAST", "DAST", "RUNTIME"}:
            tier: TriangulationTier = "FULL_TRIANGULATION"
            status: ExploitStatus = "ACTIVELY_EXPLOITED"
            final_conf = max(0.99, min(1.0, round(prob, 3)))
        elif pillars == {"DAST", "RUNTIME"}:
            tier = "DAST_RUNTIME"
            status = "ACTIVELY_EXPLOITED"
            final_conf = max(0.98, min(1.0, round(prob, 3)))
        elif pillars == {"SAST", "RUNTIME"}:
            tier = "SAST_RUNTIME"
            status = "ACTIVELY_TARGETED"
            final_conf = max(0.96, min(1.0, round(prob, 3)))
        elif pillars == {"SAST", "DAST"}:
            tier = "SAST_DAST"
            status = "CONFIRMED_EXPLOITABLE"
            final_conf = max(0.95, min(1.0, round(prob, 3)))
        elif pillars == {"RUNTIME"}:
            tier = "RUNTIME_ONLY"
            status = "ACTIVELY_TARGETED"
            final_conf = round(pillar_confidences.get("RUNTIME", 0.90), 2)
        elif pillars == {"DAST"}:
            tier = "DAST_ONLY"
            status = "CONFIRMED_EXPLOITABLE"
            final_conf = round(pillar_confidences.get("DAST", 0.90), 2)
        else:
            tier = "SAST_ONLY"
            status = "THEORETICAL"
            final_conf = round(pillar_confidences.get("SAST", 0.80), 2)

        return final_conf, tier, status

    @staticmethod
    def build_dossier(
        cwe_id: str,
        endpoint: str,
        vulnerability_title: str,
        owasp_category: str,
        severity: str,
        method: str = "GET",
        file_path: str | None = None,
        line_number: int | None = None,
        remediation_guidance: str = "",
        artifacts: list[EvidenceArtifact] | None = None,
        runtime_incidents: list[Any] | None = None,
    ) -> TriangulatedDossier:
        """Synthesize a unified dossier cross-referencing all available evidence pillars."""
        artifacts = artifacts or []
        runtime_incidents = runtime_incidents or []

        pillars: set[PillarType] = {a.pillar for a in artifacts}
        if runtime_incidents:
            pillars.add("RUNTIME")

        confidences: dict[PillarType, float] = {}
        for a in artifacts:
            confidences[a.pillar] = max(confidences.get(a.pillar, 0.0), a.confidence)

        for inc in runtime_incidents:
            inc_conf = getattr(inc, "confidence", 0.95)
            confidences["RUNTIME"] = max(confidences.get("RUNTIME", 0.0), inc_conf)

        comp_conf, tier, exploit_status = EvidenceTriangulator.calculate_composite_confidence(
            pillars, confidences
        )

        incident_ids: list[str] = [
            getattr(inc, "id", getattr(inc, "incident_id", ""))
            for inc in runtime_incidents
        ]
        adversary_sessions: list[str] = sorted(
            {
                getattr(inc, "session_id", "")
                for inc in runtime_incidents
                if getattr(inc, "session_id", None)
            }
        )

        # Build chronological timeline
        timeline: list[dict[str, Any]] = []
        for a in sorted(artifacts, key=lambda x: to_utc(x.detected_at)):
            timeline.append(
                {
                    "stage": f"PILLAR_{a.pillar}",
                    "timestamp": to_utc(a.detected_at).isoformat(),
                    "source": a.source_agent,
                    "summary": a.summary,
                    "confidence": a.confidence,
                }
            )

        for inc in runtime_incidents:
            dt = to_utc(getattr(inc, "detected_at", None))
            ts = dt.isoformat()
            timeline.append(
                {
                    "stage": "RUNTIME_ATTACK_OBSERVED",
                    "timestamp": ts,
                    "source": "Agent 7 (Runtime Security)",
                    "summary": f"Live {getattr(inc, 'attack_type', 'ATTACK')} by session {getattr(inc, 'session_id', 'unknown')}",
                    "confidence": getattr(inc, "confidence", 0.95),
                }
            )

        return TriangulatedDossier(
            cwe_id=cwe_id,
            owasp_category=owasp_category,
            vulnerability_title=vulnerability_title,
            endpoint=endpoint,
            method=method,
            file_path=file_path,
            line_number=line_number,
            triangulation_tier=tier,
            exploit_status=exploit_status,
            composite_confidence=comp_conf,
            severity=severity,
            pillars_present=sorted(pillars),
            evidence_artifacts=artifacts,
            runtime_incident_ids=[i for i in incident_ids if i],
            adversary_session_ids=adversary_sessions,
            timeline=timeline,
            remediation_guidance=remediation_guidance or "",
        )
