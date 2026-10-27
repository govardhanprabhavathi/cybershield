"""SQLAlchemy ORM models for incident orchestration workflows and cryptographic audit logging."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class IncidentWorkflowRecord(Base):
    """Database entity persisting end-to-end incident orchestration workflows."""

    __tablename__ = "incident_workflows"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: f"WF-{uuid.uuid4().hex[:8].upper()}",
    )
    state: Mapped[str] = mapped_column(String(32), default="INGESTED", index=True, nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="HIGH", nullable=False)
    priority_score: Mapped[int] = mapped_column(Integer, default=80, nullable=False)
    incident_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    dossier_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    proposal_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    normalized_route: Mapped[str] = mapped_column(String(256), default="", nullable=False)
    governance_mode: Mapped[str] = mapped_column(String(32), default="HUMAN_IN_THE_LOOP", nullable=False)
    steps: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    playbook_actions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    rca_report: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WorkflowAuditLogRecord(Base):
    """Immutable audit trail of state transitions, agent actions, and governance approvals."""

    __tablename__ = "incident_audit_logs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: f"LOG-{uuid.uuid4().hex[:8].upper()}",
    )
    workflow_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_agent: Mapped[str] = mapped_column(String(64), default="Orchestrator", nullable=False)
    reason: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
