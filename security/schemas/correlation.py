"""Schemas for multi-pillar SAST-DAST-Runtime evidence correlation and unified vulnerability dossiers."""

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(UTC)


PillarType = Literal["SAST", "DAST", "RUNTIME"]
TriangulationTier = Literal[
    "SAST_ONLY",
    "DAST_ONLY",
    "RUNTIME_ONLY",
    "SAST_DAST",
    "SAST_RUNTIME",
    "DAST_RUNTIME",
    "FULL_TRIANGULATION",
]
ExploitStatus = Literal[
    "THEORETICAL",
    "CONFIRMED_EXPLOITABLE",
    "ACTIVELY_TARGETED",
    "ACTIVELY_EXPLOITED",
]


class EvidenceArtifact(BaseModel):
    """Specific piece of evidence contributed by one of the three detection pillars."""

    artifact_id: str = Field(default_factory=lambda: f"EV-{uuid.uuid4().hex[:8].upper()}")
    pillar: PillarType
    source_agent: str
    detected_at: datetime = Field(default_factory=utcnow)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    evidence_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("detected_at", mode="before")
    @classmethod
    def ensure_tz_aware(cls, v: Any) -> datetime:
        if v is None:
            return datetime.now(UTC)
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v


class TriangulatedDossier(BaseModel):
    """Unified vulnerability dossier cross-referencing static AST code, dynamic HTTP probe, and runtime incident."""

    dossier_id: str = Field(default_factory=lambda: f"DOS-{uuid.uuid4().hex[:8].upper()}")
    cwe_id: str
    owasp_category: str
    vulnerability_title: str
    endpoint: str
    method: str = "GET"
    file_path: str | None = None
    line_number: int | None = None
    triangulation_tier: TriangulationTier = "SAST_ONLY"
    exploit_status: ExploitStatus = "THEORETICAL"
    composite_confidence: float = Field(default=0.80, ge=0.0, le=1.0)
    severity: str = "MEDIUM"
    pillars_present: list[PillarType] = Field(default_factory=list)
    evidence_artifacts: list[EvidenceArtifact] = Field(default_factory=list)
    runtime_incident_ids: list[str] = Field(default_factory=list)
    adversary_session_ids: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    remediation_guidance: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    last_updated_at: datetime = Field(default_factory=utcnow)


class TriangulationReport(BaseModel):
    """Aggregated platform assessment summarizing multi-pillar evidence correlation across all endpoints."""

    report_id: str = Field(default_factory=lambda: f"REP-TRI-{uuid.uuid4().hex[:8].upper()}")
    generated_at: datetime = Field(default_factory=utcnow)
    total_dossiers: int = 0
    fully_triangulated_count: int = 0
    actively_exploited_count: int = 0
    dossiers_by_tier: dict[str, int] = Field(default_factory=dict)
    dossiers_by_status: dict[str, int] = Field(default_factory=dict)
    dossiers: list[TriangulatedDossier] = Field(default_factory=list)
