from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class WorkflowState(str, Enum):
    """Lifecycle states of the AI Security Incident Orchestrator state machine."""

    INGESTED = "INGESTED"
    CONTAINING = "CONTAINING"
    TRIANGULATING = "TRIANGULATING"
    DRAFTING_PATCH = "DRAFTING_PATCH"
    VERIFYING_PATCH = "VERIFYING_PATCH"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    AUTO_DEPLOYING = "AUTO_DEPLOYING"
    VERIFYING_RUNTIME = "VERIFYING_RUNTIME"
    RESOLVED = "RESOLVED"
    ROLLED_BACK = "ROLLED_BACK"
    ESCALATED_HUMAN = "ESCALATED_HUMAN"
    FAILED = "FAILED"


class GovernanceMode(str, Enum):
    """Governance mode controlling autonomous deployment vs human-in-the-loop."""

    FULLY_AUTONOMOUS = "FULLY_AUTONOMOUS"
    HUMAN_IN_THE_LOOP = "HUMAN_IN_THE_LOOP"


class WorkflowStepRecord(BaseModel):
    """Record of an individual agent step execution within the workflow."""

    model_config = ConfigDict(extra="ignore")

    step_name: str
    agent_name: str
    status: str  # "COMPLETED", "FAILED", "SKIPPED", "RUNNING"
    duration_ms: float = 0.0
    inputs: dict[str, Any] = Field(default_factory=dict)
    outputs: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PlaybookAction(BaseModel):
    """Individual playbook action item executed or recommended."""

    model_config = ConfigDict(extra="ignore")

    action_id: str
    action_type: str  # "CONTAIN_SESSION", "NOTIFY_OPS", "TRIGGER_SCAN", "HOTPATCH", "ROTATE_SECRET"
    description: str
    status: str  # "EXECUTED", "PENDING", "FAILED"
    automated: bool = True
    executed_at: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class IncidentRCA(BaseModel):
    """Structured Root Cause Analysis (RCA) produced for an incident."""

    model_config = ConfigDict(extra="ignore")

    cwe_id: str
    cwe_title: str
    root_cause_summary: str
    vulnerable_file: str | None = None
    vulnerable_line: int | None = None
    attack_vector: str
    blast_radius: str
    technical_details: str
    preventive_recommendations: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class WorkflowTriggerRequest(BaseModel):
    """Request payload to initiate an incident orchestration workflow."""

    model_config = ConfigDict(extra="ignore")

    cwe_id: str
    incident_id: str | None = None
    dossier_id: str | None = None
    session_id: str | None = None
    normalized_route: str
    attack_payload: str | None = None
    severity: str = "HIGH"
    governance_mode: GovernanceMode = GovernanceMode.HUMAN_IN_THE_LOOP
    auto_apply: bool = False


class WorkflowApprovalRequest(BaseModel):
    """Request payload for human approval or rejection of a pending patch."""

    model_config = ConfigDict(extra="ignore")

    approved: bool
    reviewer: str = "security_lead"
    comments: str | None = None


class WorkflowDetailResponse(BaseModel):
    """Complete detail view of an incident workflow."""

    model_config = ConfigDict(extra="ignore")

    workflow_id: str
    state: WorkflowState
    cwe_id: str
    severity: str
    priority_score: int
    incident_id: str | None = None
    dossier_id: str | None = None
    proposal_id: str | None = None
    session_id: str | None = None
    normalized_route: str
    governance_mode: GovernanceMode
    steps: list[WorkflowStepRecord] = Field(default_factory=list)
    playbook_actions: list[PlaybookAction] = Field(default_factory=list)
    rca: IncidentRCA | None = None
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None
