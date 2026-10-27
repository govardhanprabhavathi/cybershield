"""Integration tests for MasterOrchestratorAgent lifecycle and governance gates."""

import pytest
from app.models.workflow import IncidentWorkflowRecord, WorkflowAuditLogRecord
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.orchestrator.orchestrator_agent import MasterOrchestratorAgent
from security.schemas.orchestrator import GovernanceMode, WorkflowState


@pytest.mark.asyncio
async def test_orchestrator_autonomous_end_to_end_resolution(db_session: AsyncSession):
    """Verify that an incident with FULLY_AUTONOMOUS governance transitions from INGESTED through to RESOLVED."""
    agent = MasterOrchestratorAgent()
    workflow = IncidentWorkflowRecord(
        id="WF-TEST-AUTO-01",
        state=WorkflowState.INGESTED.value,
        cwe_id="CWE-89",
        severity="MEDIUM",
        priority_score=60,
        session_id="sess_bot_sqli",
        normalized_route="/api/v1/products/search",
        governance_mode=GovernanceMode.FULLY_AUTONOMOUS.value,
        steps=[],
        playbook_actions=[],
        rca_report={},
    )
    db_session.add(workflow)
    await db_session.commit()
    await db_session.refresh(workflow)

    # Execute workflow to completion
    result = await agent.execute_workflow_to_completion(db_session, workflow)

    assert result.state == WorkflowState.RESOLVED.value
    assert result.proposal_id is not None
    assert len(result.steps) >= 5
    assert result.rca_report is not None
    assert result.rca_report.get("cwe_id") == "CWE-89"
    assert result.closed_at is not None

    # Check audit log sequence
    stmt = (
        select(WorkflowAuditLogRecord)
        .where(WorkflowAuditLogRecord.workflow_id == "WF-TEST-AUTO-01")
        .order_by(WorkflowAuditLogRecord.timestamp.asc())
    )
    logs = list((await db_session.scalars(stmt)).all())
    states_traversed = [l.to_state for l in logs]
    assert WorkflowState.CONTAINING.value in states_traversed
    assert WorkflowState.TRIANGULATING.value in states_traversed
    assert WorkflowState.DRAFTING_PATCH.value in states_traversed
    assert WorkflowState.VERIFYING_PATCH.value in states_traversed
    assert WorkflowState.AUTO_DEPLOYING.value in states_traversed
    assert WorkflowState.VERIFYING_RUNTIME.value in states_traversed
    assert WorkflowState.RESOLVED.value in states_traversed


@pytest.mark.asyncio
async def test_orchestrator_human_in_the_loop_approval_gate(db_session: AsyncSession):
    """Verify that HIGH severity incidents pause at AWAITING_APPROVAL and proceed once approved."""
    agent = MasterOrchestratorAgent()
    workflow = IncidentWorkflowRecord(
        id="WF-TEST-HITL-02",
        state=WorkflowState.INGESTED.value,
        cwe_id="CWE-284",
        severity="HIGH",
        priority_score=85,
        session_id="sess_cross_tenant_probe",
        normalized_route="/api/v1/orders/{order_id}",
        governance_mode=GovernanceMode.HUMAN_IN_THE_LOOP.value,
        steps=[],
        playbook_actions=[],
        rca_report={},
    )
    db_session.add(workflow)
    await db_session.commit()
    await db_session.refresh(workflow)

    # Initial execution should pause at AWAITING_APPROVAL gate
    result_paused = await agent.execute_workflow_to_completion(db_session, workflow)
    assert result_paused.state == WorkflowState.AWAITING_APPROVAL.value
    assert result_paused.proposal_id is not None

    # Human operator approves patch
    result_approved = await agent.approve_and_deploy(
        db_session, result_paused, reviewer="lead_security_engineer"
    )
    assert result_approved.state == WorkflowState.RESOLVED.value
    assert result_approved.closed_at is not None


@pytest.mark.asyncio
async def test_orchestrator_human_rejection_and_escalation(db_session: AsyncSession):
    """Verify that human rejection escalates workflow to ESCALATED_HUMAN."""
    agent = MasterOrchestratorAgent()
    workflow = IncidentWorkflowRecord(
        id="WF-TEST-REJECT-03",
        state=WorkflowState.AWAITING_APPROVAL.value,
        cwe_id="CWE-840",
        severity="CRITICAL",
        priority_score=95,
        normalized_route="/api/v1/cart/items",
        governance_mode=GovernanceMode.HUMAN_IN_THE_LOOP.value,
        steps=[],
        playbook_actions=[],
        rca_report={},
    )
    db_session.add(workflow)
    await db_session.commit()
    await db_session.refresh(workflow)

    result_escalated = await agent.reject_and_escalate(
        db_session, workflow, reviewer="soc_analyst", reason="Requires business stakeholder signoff"
    )
    assert result_escalated.state == WorkflowState.ESCALATED_HUMAN.value


@pytest.mark.asyncio
async def test_orchestrator_rollback_workflow(db_session: AsyncSession):
    """Verify rollback capability reverting patch and setting ROLLED_BACK state."""
    agent = MasterOrchestratorAgent()
    workflow = IncidentWorkflowRecord(
        id="WF-TEST-ROLLBACK-04",
        state=WorkflowState.VERIFYING_RUNTIME.value,
        cwe_id="CWE-89",
        severity="HIGH",
        priority_score=80,
        normalized_route="/api/v1/products/search",
        governance_mode=GovernanceMode.FULLY_AUTONOMOUS.value,
        steps=[],
        playbook_actions=[],
        rca_report={},
    )
    db_session.add(workflow)
    await db_session.commit()
    await db_session.refresh(workflow)

    rolled_back = await agent.rollback_workflow(db_session, workflow, actor="secops_sre")
    assert rolled_back.state == WorkflowState.ROLLED_BACK.value
