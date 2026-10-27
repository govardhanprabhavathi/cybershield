"""REST API endpoints for the AI Security Orchestrator and incident workflow engine."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from security.schemas.orchestrator import (
    WorkflowApprovalRequest,
    WorkflowTriggerRequest,
)
from services.orchestrator.orchestrator_service import OrchestratorService

router = APIRouter(prefix="/security/v1/orchestrator", tags=["AI Security Orchestrator"])
_orchestrator_service = OrchestratorService()


@router.post(
    "/workflows/trigger",
    response_model=dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Incident Response Workflow",
)
async def trigger_workflow(
    req: WorkflowTriggerRequest,
    db: AsyncSession = Depends(get_db),
):
    """Launch an autonomous multi-agent incident workflow for a vulnerability or runtime threat."""
    try:
        rec = await _orchestrator_service.trigger_workflow(db, req)
        return {
            "status": "success",
            "message": f"Workflow {rec.id} initiated in state '{rec.state}'",
            "workflow": {
                "id": rec.id,
                "state": rec.state,
                "cwe_id": rec.cwe_id,
                "severity": rec.severity,
                "proposal_id": rec.proposal_id,
                "dossier_id": rec.dossier_id,
                "steps_count": len(rec.steps or []),
            },
        }
    except Exception as ex:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate workflow: {ex!s}",
        )


@router.get(
    "/workflows",
    response_model=list[dict[str, Any]],
    summary="List Incident Workflows",
)
async def list_workflows(
    state: str | None = Query(None, description="Filter by state (e.g. AWAITING_APPROVAL, RESOLVED)"),
    cwe_id: str | None = Query(None, description="Filter by CWE ID"),
    severity: str | None = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve history of incident workflows matching criteria."""
    records = await _orchestrator_service.list_workflows(
        db, state=state, cwe_id=cwe_id, severity=severity, limit=limit
    )
    return [
        {
            "id": r.id,
            "state": r.state,
            "cwe_id": r.cwe_id,
            "severity": r.severity,
            "priority_score": r.priority_score,
            "proposal_id": r.proposal_id,
            "dossier_id": r.dossier_id,
            "governance_mode": r.governance_mode,
            "steps_count": len(r.steps or []),
            "created_at": r.created_at.isoformat(),
            "closed_at": r.closed_at.isoformat() if r.closed_at else None,
        }
        for r in records
    ]


@router.get(
    "/workflows/{workflow_id}",
    response_model=dict[str, Any],
    summary="Get Detailed Workflow Execution",
)
async def get_workflow_detail(
    workflow_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve full workflow state, agent execution steps, playbook actions, and RCA."""
    rec = await _orchestrator_service.get_workflow(db, workflow_id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow not found")

    return {
        "id": rec.id,
        "state": rec.state,
        "cwe_id": rec.cwe_id,
        "severity": rec.severity,
        "priority_score": rec.priority_score,
        "incident_id": rec.incident_id,
        "dossier_id": rec.dossier_id,
        "proposal_id": rec.proposal_id,
        "session_id": rec.session_id,
        "normalized_route": rec.normalized_route,
        "governance_mode": rec.governance_mode,
        "steps": rec.steps or [],
        "playbook_actions": rec.playbook_actions or [],
        "rca_report": rec.rca_report or {},
        "error_message": rec.error_message,
        "created_at": rec.created_at.isoformat(),
        "updated_at": rec.updated_at.isoformat(),
        "closed_at": rec.closed_at.isoformat() if rec.closed_at else None,
    }


@router.post(
    "/workflows/{workflow_id}/approve",
    response_model=dict[str, Any],
    summary="Human-in-the-Loop Approval Gate",
)
async def approve_workflow(
    workflow_id: str,
    req: WorkflowApprovalRequest,
    db: AsyncSession = Depends(get_db),
):
    """Human approval to deploy verified patch to production or reject/escalate."""
    try:
        rec = await _orchestrator_service.approve_workflow(db, workflow_id, req)
        return {
            "status": "success",
            "message": f"Workflow {workflow_id} processed by reviewer '{req.reviewer}'. New state: '{rec.state}'",
            "state": rec.state,
        }
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))
    except Exception as ex:  # noqa: BLE001
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))


@router.post(
    "/workflows/{workflow_id}/rollback",
    response_model=dict[str, Any],
    summary="Rollback Applied Codebase Patch",
)
async def rollback_workflow(
    workflow_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Revert applied patch back to verified pre-remediation baseline."""
    try:
        rec = await _orchestrator_service.rollback_workflow(db, workflow_id)
        return {
            "status": "success",
            "message": f"Workflow {workflow_id} rolled back to pre-remediation baseline.",
            "state": rec.state,
        }
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))


@router.post(
    "/workflows/{workflow_id}/retry",
    response_model=dict[str, Any],
    summary="Retry Failed Workflow",
)
async def retry_workflow(
    workflow_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Retry a failed workflow step execution."""
    try:
        rec = await _orchestrator_service.retry_workflow(db, workflow_id)
        return {
            "status": "success",
            "message": f"Workflow {workflow_id} re-triggered; current state: '{rec.state}'",
            "state": rec.state,
        }
    except ValueError as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))


@router.get(
    "/workflows/{workflow_id}/rca",
    response_model=dict[str, Any],
    summary="Get Root Cause Analysis & Blast Radius",
)
async def get_workflow_rca(
    workflow_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve structured Root Cause Analysis report for workflow."""
    rec = await _orchestrator_service.get_workflow(db, workflow_id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow not found")

    return rec.rca_report or {"message": "RCA not yet compiled for this workflow"}
