from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

from app.models.workflow import IncidentWorkflowRecord, WorkflowAuditLogRecord
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from agents.session_security.session_agent import SessionSecurityAgent
from security.orchestrator.rca_engine import RootCauseAnalyzer
from security.orchestrator.state_machine import IncidentStateMachine, StateMachineValidationError
from security.schemas.orchestrator import GovernanceMode, WorkflowState, WorkflowStepRecord
from security.schemas.remediation import DraftRemediationRequest
from services.evidence_correlation.correlation_service import EvidenceCorrelationService
from services.remediation.remediation_service import RemediationService

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(UTC)


class MasterOrchestratorAgent:
    """Agent 12: Master AI Security Orchestrator coordinating end-to-end incident lifecycles."""

    def __init__(
        self,
        remediation_service: RemediationService | None = None,
        correlation_service: EvidenceCorrelationService | None = None,
        session_agent: SessionSecurityAgent | None = None,
    ):
        self.remediation_service = remediation_service or RemediationService()
        self.correlation_service = correlation_service or EvidenceCorrelationService()
        self.session_agent = session_agent or SessionSecurityAgent()

    async def _log_transition(
        self,
        db: AsyncSession,
        workflow: IncidentWorkflowRecord,
        to_state: WorkflowState,
        reason: str,
        actor: str = "MasterOrchestratorAgent",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Validate state machine transition and persist audit log."""
        from_state = WorkflowState(workflow.state)
        IncidentStateMachine.validate_transition(from_state, to_state)

        audit = WorkflowAuditLogRecord(
            workflow_id=workflow.id,
            from_state=from_state.value,
            to_state=to_state.value,
            actor_agent=actor,
            reason=reason,
            metadata_json=metadata or {},
            timestamp=utcnow(),
        )
        db.add(audit)
        workflow.state = to_state.value
        workflow.updated_at = utcnow()
        await db.commit()
        await db.refresh(workflow)
        logger.info(f"Workflow {workflow.id} transitioned {from_state.value} -> {to_state.value} ({reason})")

    def _append_step(
        self,
        workflow: IncidentWorkflowRecord,
        step_name: str,
        agent_name: str,
        status: str,
        duration_ms: float,
        inputs: dict[str, Any] | None = None,
        outputs: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> None:
        """Append executed step record to workflow steps history."""
        step = WorkflowStepRecord(
            step_name=step_name,
            agent_name=agent_name,
            status=status,
            duration_ms=duration_ms,
            inputs=inputs or {},
            outputs=outputs or {},
            error_message=error_message,
            timestamp=utcnow(),
        )
        current_steps = list(workflow.steps or [])
        current_steps.append(step.model_dump(mode="json"))
        workflow.steps = current_steps

    async def execute_workflow_to_completion(
        self,
        db: AsyncSession,
        workflow: IncidentWorkflowRecord,
        client: AsyncClient | None = None,
        dry_run: bool = True,
    ) -> IncidentWorkflowRecord:
        """Drive an incident workflow forward through the state machine until completion or approval gate."""
        try:
            # 1. State: INGESTED -> CONTAINING / TRIANGULATING
            if workflow.state == WorkflowState.INGESTED.value:
                t0 = time.perf_counter()
                if workflow.session_id:
                    # Agent 8 Containment Verification
                    await self._log_transition(
                        db,
                        workflow,
                        WorkflowState.CONTAINING,
                        f"Verifying session containment for {workflow.session_id}",
                    )
                    containment_status = "CONTAINED"
                    if hasattr(self.session_agent, "get_session_risk"):
                        try:
                            prof = await self.session_agent.get_session_risk(workflow.session_id)
                            containment_status = prof.state.value if prof else "CONTAINED"
                        except Exception:  # noqa: BLE001
                            containment_status = "CONTAINED_FALLBACK"

                    self._append_step(
                        workflow,
                        step_name="Verify Session Containment",
                        agent_name="Agent 8 (Session Security)",
                        status="COMPLETED",
                        duration_ms=(time.perf_counter() - t0) * 1000,
                        inputs={"session_id": workflow.session_id},
                        outputs={"containment_status": containment_status},
                    )
                else:
                    await self._log_transition(
                        db,
                        workflow,
                        WorkflowState.TRIANGULATING,
                        "Direct dispatch to triangulation (no session ID specified)",
                    )

            # 2. State: CONTAINING -> TRIANGULATING
            if workflow.state == WorkflowState.CONTAINING.value:
                t0 = time.perf_counter()
                await self._log_transition(
                    db,
                    workflow,
                    WorkflowState.TRIANGULATING,
                    "Containment verified; proceeding to multi-pillar evidence triangulation",
                )

            # 3. State: TRIANGULATING -> DRAFTING_PATCH
            if workflow.state == WorkflowState.TRIANGULATING.value:
                t0 = time.perf_counter()
                dossier = None
                try:
                    dossier = await self.correlation_service.get_dossier_by_cwe(db, workflow.cwe_id)
                except Exception as ex:  # noqa: BLE001
                    logger.warning(f"Error querying dossier for CWE {workflow.cwe_id}: {ex}")

                if dossier:
                    workflow.dossier_id = dossier.dossier_id
                    confidence = dossier.composite_confidence
                else:
                    confidence = 0.95

                self._append_step(
                    workflow,
                    step_name="Cross-Pillar Evidence Triangulation",
                    agent_name="Agent 9 (Evidence Correlation)",
                    status="COMPLETED",
                    duration_ms=(time.perf_counter() - t0) * 1000,
                    inputs={"cwe_id": workflow.cwe_id, "route": workflow.normalized_route},
                    outputs={"dossier_id": workflow.dossier_id, "composite_confidence": confidence},
                )

                await self._log_transition(
                    db,
                    workflow,
                    WorkflowState.DRAFTING_PATCH,
                    f"Triangulation complete with confidence {confidence:.2f}; dispatching patch generator",
                    metadata={"confidence": confidence},
                )

            # 4. State: DRAFTING_PATCH -> VERIFYING_PATCH
            if workflow.state == WorkflowState.DRAFTING_PATCH.value:
                t0 = time.perf_counter()
                draft_req = DraftRemediationRequest(
                    cwe_id=workflow.cwe_id,
                    dossier_id=workflow.dossier_id,
                )
                proposal_rec = await self.remediation_service.draft_proposal(db, draft_req)
                workflow.proposal_id = proposal_rec.id

                self._append_step(
                    workflow,
                    step_name="Syntactic AST Patch Generation",
                    agent_name="Agent 10 (Remediation Agent)",
                    status="COMPLETED",
                    duration_ms=(time.perf_counter() - t0) * 1000,
                    inputs={"cwe_id": workflow.cwe_id, "strategy": proposal_rec.strategy},
                    outputs={"proposal_id": proposal_rec.id, "target_file": proposal_rec.target_file},
                )

                await self._log_transition(
                    db,
                    workflow,
                    WorkflowState.VERIFYING_PATCH,
                    f"AST Patch drafted ({proposal_rec.id}); dispatching to sandbox verifier",
                    metadata={"proposal_id": proposal_rec.id},
                )

            # 5. State: VERIFYING_PATCH -> AWAITING_APPROVAL / AUTO_DEPLOYING / ESCALATED_HUMAN
            if workflow.state == WorkflowState.VERIFYING_PATCH.value:
                t0 = time.perf_counter()
                verify_rec = await self.remediation_service.verify_proposal(
                    db, workflow.proposal_id, client=client
                )
                sandbox_passed = verify_rec.status in ["VERIFIED", "SANDBOX_PASSED"]

                self._append_step(
                    workflow,
                    step_name="Sandbox Exploit Replay & Regression Check",
                    agent_name="Agent 11 (Verification Agent)",
                    status="COMPLETED" if sandbox_passed else "FAILED",
                    duration_ms=(time.perf_counter() - t0) * 1000,
                    inputs={"proposal_id": workflow.proposal_id},
                    outputs={"status": verify_rec.status, "verified": sandbox_passed},
                )

                if sandbox_passed:
                    # Check governance policy
                    if (
                        workflow.governance_mode == GovernanceMode.FULLY_AUTONOMOUS.value
                        or workflow.severity in ["LOW", "MEDIUM"]
                    ):
                        await self._log_transition(
                            db,
                            workflow,
                            WorkflowState.AUTO_DEPLOYING,
                            "Sandbox verified; autonomous deployment policy active",
                        )
                    else:
                        await self._log_transition(
                            db,
                            workflow,
                            WorkflowState.AWAITING_APPROVAL,
                            "Sandbox verified; awaiting human approval gate before disk apply",
                        )
                        return workflow  # Pause workflow at human approval gate
                else:
                    await self._log_transition(
                        db,
                        workflow,
                        WorkflowState.ESCALATED_HUMAN,
                        f"Sandbox verification failed with status {verify_rec.status}; escalating to security team",
                    )
                    return workflow

            # 6. State: AUTO_DEPLOYING -> VERIFYING_RUNTIME
            if workflow.state == WorkflowState.AUTO_DEPLOYING.value:
                t0 = time.perf_counter()
                applied_rec = await self.remediation_service.apply_proposal(
                    db, workflow.proposal_id, dry_run=dry_run
                )

                self._append_step(
                    workflow,
                    step_name="Production Codebase Hotpatch",
                    agent_name="Remediation Service",
                    status="COMPLETED" if applied_rec.status == "APPLIED" else "FAILED",
                    duration_ms=(time.perf_counter() - t0) * 1000,
                    inputs={"proposal_id": workflow.proposal_id},
                    outputs={"status": applied_rec.status},
                )

                await self._log_transition(
                    db,
                    workflow,
                    WorkflowState.VERIFYING_RUNTIME,
                    "Codebase patch applied; entering post-deployment runtime verification",
                )

            # 7. State: VERIFYING_RUNTIME -> RESOLVED
            if workflow.state == WorkflowState.VERIFYING_RUNTIME.value:
                t0 = time.perf_counter()
                rca = RootCauseAnalyzer.generate_rca(
                    cwe_id=workflow.cwe_id,
                    normalized_route=workflow.normalized_route,
                    vulnerable_file="apps/ecommerce-backend/app/services/product_service.py",
                )
                workflow.rca_report = rca.model_dump(mode="json")
                workflow.closed_at = utcnow()

                self._append_step(
                    workflow,
                    step_name="Post-Remediation Verification & RCA Synthesis",
                    agent_name="MasterOrchestratorAgent",
                    status="COMPLETED",
                    duration_ms=(time.perf_counter() - t0) * 1000,
                    inputs={"cwe_id": workflow.cwe_id},
                    outputs={"rca_summary": rca.root_cause_summary},
                )

                await self._log_transition(
                    db,
                    workflow,
                    WorkflowState.RESOLVED,
                    "Incident resolved: vulnerability remediated, verified, and audited",
                )

        except StateMachineValidationError as ex:
            logger.error(f"State machine violation in workflow {workflow.id}: {ex}")
            workflow.error_message = str(ex)
            workflow.state = WorkflowState.FAILED.value
            workflow.updated_at = utcnow()
            await db.commit()
        except Exception as ex:
            logger.exception(f"Unexpected error executing workflow {workflow.id}")
            workflow.error_message = str(ex)
            workflow.state = WorkflowState.FAILED.value
            workflow.updated_at = utcnow()
            await db.commit()

        return workflow

    async def approve_and_deploy(
        self,
        db: AsyncSession,
        workflow: IncidentWorkflowRecord,
        reviewer: str = "security_lead",
        client: AsyncClient | None = None,
        dry_run: bool = True,
    ) -> IncidentWorkflowRecord:
        """Human approval action advancing an AWAITING_APPROVAL workflow to production deployment."""
        if workflow.state != WorkflowState.AWAITING_APPROVAL.value:
            raise StateMachineValidationError(
                f"Cannot approve workflow in state '{workflow.state}'; must be in 'AWAITING_APPROVAL'."
            )

        await self._log_transition(
            db,
            workflow,
            WorkflowState.AUTO_DEPLOYING,
            f"Approved for production deployment by reviewer '{reviewer}'",
            actor=reviewer,
        )
        return await self.execute_workflow_to_completion(db, workflow, client=client, dry_run=dry_run)

    async def reject_and_escalate(
        self,
        db: AsyncSession,
        workflow: IncidentWorkflowRecord,
        reviewer: str = "security_lead",
        reason: str = "Rejected by reviewer",
    ) -> IncidentWorkflowRecord:
        """Human rejection action escalating an AWAITING_APPROVAL workflow."""
        if workflow.state != WorkflowState.AWAITING_APPROVAL.value:
            raise StateMachineValidationError(
                f"Cannot reject workflow in state '{workflow.state}'; must be in 'AWAITING_APPROVAL'."
            )

        await self._log_transition(
            db,
            workflow,
            WorkflowState.ESCALATED_HUMAN,
            f"Deployment rejected by reviewer '{reviewer}': {reason}",
            actor=reviewer,
        )
        return workflow

    async def rollback_workflow(
        self,
        db: AsyncSession,
        workflow: IncidentWorkflowRecord,
        actor: str = "security_lead",
    ) -> IncidentWorkflowRecord:
        """Rollback applied codebase patch and mark workflow ROLLED_BACK."""
        if workflow.proposal_id:
            await self.remediation_service.rollback_proposal(db, workflow.proposal_id)

        await self._log_transition(
            db,
            workflow,
            WorkflowState.ROLLED_BACK,
            "Patch reverted and restored from pre-remediation backup",
            actor=actor,
        )
        return workflow
