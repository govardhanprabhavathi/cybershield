"""Pydantic schemas for AI-driven automated remediation, AST patch drafting, and sandbox verification."""

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(UTC)


PatchStrategy = Literal[
    "AST_TRANSFORM",
    "PARAMETERIZATION",
    "AUTHORIZATION_GATE",
    "INPUT_VALIDATION",
    "SECRET_ISOLATION",
]

RemediationStatus = Literal[
    "DRAFTED",
    "VERIFYING",
    "VERIFIED",
    "FAILED_VERIFICATION",
    "SYNTAX_ERROR",
    "REGRESSION_DETECTED",
    "EXPLOIT_STILL_FEASIBLE",
    "APPLIED",
    "REJECTED",
    "ROLLED_BACK",
]


class ASTDiff(BaseModel):
    """Detailed AST diff and code replacement context."""

    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    original_code: str
    patched_code: str
    unified_diff: str
    explanation: str
    strategy: PatchStrategy = "AST_TRANSFORM"


class ExploitReplayTest(BaseModel):
    """Results from replaying a dynamic DAST probe against patched code."""

    probe_name: str
    target_endpoint: str
    attack_payload: str
    expected_status_code: int = 403
    actual_status_code: int | None = None
    exploit_neutralized: bool = True
    evidence: dict[str, Any] = Field(default_factory=dict)


class VerificationCheck(BaseModel):
    """Individual assertion performed during sandbox verification."""

    check_name: str
    passed: bool
    detail: str = ""


class VerificationReport(BaseModel):
    """Formal verification report compiled by Agent 11 in isolated sandbox."""

    verification_id: str = Field(default_factory=lambda: f"VER-{uuid.uuid4().hex[:8].upper()}")
    proposal_id: str
    status: Literal[
        "VERIFIED",
        "SYNTAX_ERROR",
        "REGRESSION_DETECTED",
        "EXPLOIT_STILL_FEASIBLE",
        "FAILED_VERIFICATION",
    ] = "VERIFIED"
    syntax_valid: bool = True
    regression_free: bool = True
    exploit_neutralized: bool = True
    execution_time_ms: float = 0.0
    checks: list[VerificationCheck] = Field(default_factory=list)
    replay_results: list[ExploitReplayTest] = Field(default_factory=list)
    verified_at: datetime = Field(default_factory=utcnow)

    @field_validator("verified_at", mode="before")
    @classmethod
    def ensure_tz_aware(cls, v: Any) -> datetime:
        if v is None:
            return utcnow()
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v


class RemediationProposal(BaseModel):
    """Unified remediation proposal containing the AST diff and verification state."""

    proposal_id: str = Field(default_factory=lambda: f"REM-{uuid.uuid4().hex[:8].upper()}")
    dossier_id: str | None = None
    finding_id: str | None = None
    cwe_id: str
    vulnerability_title: str
    target_file: str
    status: RemediationStatus = "DRAFTED"
    diff: ASTDiff
    verification_report: VerificationReport | None = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def ensure_tz_aware(cls, v: Any) -> datetime:
        if v is None:
            return utcnow()
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v


class DraftRemediationRequest(BaseModel):
    """API payload requesting automated patch generation."""

    dossier_id: str | None = None
    finding_id: str | None = None
    cwe_id: str | None = None
    target_file: str | None = None
