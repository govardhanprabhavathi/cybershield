from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from app.models.workflow import IncidentWorkflowRecord, WorkflowAuditLogRecord
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.orchestrator.orchestrator_agent import MasterOrchestratorAgent
from security.orchestrator.playbooks import SecurityPlaybookRunner
from security.schemas.orchestrator import (
    WorkflowApprovalRequest,
    WorkflowState,
    WorkflowTriggerRequest,
)

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(UTC)


class OrchestratorService:
    """Service managing persistence, queries, and execution of incident workflows."""

    def __init__(self, orchestrator_agent: MasterOrchestratorAgent | None = None):
        self.orchestrator_agent = orchestrator_agent or MasterOrchestratorAgent()

    async def trigger_workflow(
        self,
        db: AsyncSession,
        req: WorkflowTriggerRequest,
        client: AsyncClient | None = None,
    ) -> IncidentWorkflowRecord:
        """Create and initiate execution of a new incident workflow."""
        workflow_id = f"WF-{uuid.uuid4().hex[:8].upper()}"
        playbook = SecurityPlaybookRunner.get_playbook_actions(req.cwe_id, req.session_id)

        rec = IncidentWorkflowRecord(
            id=workflow_id,
            state=WorkflowState.INGESTED.value,
            cwe_id=req.cwe_id,
            severity=req.severity,
            priority_score=95 if req.severity == "CRITICAL" else 80 if req.severity == "HIGH" else 50,
            incident_id=req.incident_id,
            dossier_id=req.dossier_id,
            session_id=req.session_id,
            normalized_route=req.normalized_route,
            governance_mode=req.governance_mode.value,
            steps=[],
            playbook_actions=[a.model_dump(mode="json") for a in playbook],
            rca_report={},
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(rec)

        # Ingestion audit log
        init_audit = WorkflowAuditLogRecord(
            workflow_id=workflow_id,
            from_state="NONE",
            to_state=WorkflowState.INGESTED.value,
            actor_agent="MasterOrchestratorAgent",
            reason=f"Incident ingested for weakness {req.cwe_id} on {req.normalized_route}",
            metadata_json={"severity": req.severity, "session_id": req.session_id},
            timestamp=utcnow(),
        )
        db.add(init_audit)
        await db.commit()
        await db.refresh(rec)

        logger.info(f"Triggered workflow {workflow_id} for {req.cwe_id}")
        return await self.orchestrator_agent.execute_workflow_to_completion(db, rec, client=client)

    async def list_workflows(
        self,
        db: AsyncSession,
        state: str | None = None,
        cwe_id: str | None = None,
        severity: str | None = None,
        limit: int = 50,
    ) -> list[IncidentWorkflowRecord]:
        """Query workflow records matching filters."""
        stmt = select(IncidentWorkflowRecord).order_by(IncidentWorkflowRecord.created_at.desc()).limit(limit)
        if state:
            stmt = stmt.where(IncidentWorkflowRecord.state == state)
        if cwe_id:
            stmt = stmt.where(IncidentWorkflowRecord.cwe_id == cwe_id)
        if severity:
            stmt = stmt.where(IncidentWorkflowRecord.severity == severity)

        res = await db.scalars(stmt)
        return list(res.all())

    async def get_workflow(
        self,
        db: AsyncSession,
        workflow_id: str,
    ) -> IncidentWorkflowRecord | None:
        """Fetch specific workflow by ID."""
        stmt = select(IncidentWorkflowRecord).where(IncidentWorkflowRecord.id == workflow_id)
        return await db.scalar(stmt)

    async def approve_workflow(
        self,
        db: AsyncSession,
        workflow_id: str,
        req: WorkflowApprovalRequest,
        client: AsyncClient | None = None,
    ) -> IncidentWorkflowRecord:
        """Approve pending workflow and continue deployment."""
        rec = await self.get_workflow(db, workflow_id)
        if not rec:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        if req.approved:
            return await self.orchestrator_agent.approve_and_deploy(
                db, rec, reviewer=req.reviewer, client=client
            )
        else:
            return await self.orchestrator_agent.reject_and_escalate(
                db, rec, reviewer=req.reviewer, reason=req.comments or "Rejected by human operator"
            )

    async def rollback_workflow(
        self,
        db: AsyncSession,
        workflow_id: str,
        actor: str = "security_lead",
    ) -> IncidentWorkflowRecord:
        """Rollback applied patch associated with workflow."""
        rec = await self.get_workflow(db, workflow_id)
        if not rec:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        return await self.orchestrator_agent.rollback_workflow(db, rec, actor=actor)

    async def retry_workflow(
        self,
        db: AsyncSession,
        workflow_id: str,
        client: AsyncClient | None = None,
    ) -> IncidentWorkflowRecord:
        """Retry a failed workflow."""
        rec = await self.get_workflow(db, workflow_id)
        if not rec:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        rec.state = WorkflowState.TRIANGULATING.value
        rec.error_message = None
        rec.updated_at = utcnow()
        await db.commit()
        await db.refresh(rec)

        return await self.orchestrator_agent.execute_workflow_to_completion(db, rec, client=client)
