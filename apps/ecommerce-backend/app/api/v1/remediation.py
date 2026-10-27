"""Automated remediation, AST patch drafting, and sandbox verification REST API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.remediation import RemediationProposalRecord
from security.schemas.remediation import (
    ASTDiff,
    DraftRemediationRequest,
    RemediationProposal,
    VerificationReport,
)
from services.remediation.remediation_service import RemediationService

router = APIRouter()
service = RemediationService()


def _format_proposal(record: RemediationProposalRecord) -> RemediationProposal:
    """Format SQLAlchemy proposal record into Pydantic schema."""
    report = None
    if record.verification_report:
        report = VerificationReport(**record.verification_report)

    diff = ASTDiff(
        file_path=record.target_file,
        line_start=record.line_start,
        line_end=record.line_end,
        original_code=record.original_code,
        patched_code=record.patched_code,
        unified_diff=record.unified_diff,
        explanation=record.explanation,
        strategy=record.strategy,  # type: ignore[arg-type]
    )

    return RemediationProposal(
        proposal_id=record.id,
        dossier_id=record.dossier_id,
        finding_id=record.finding_id,
        cwe_id=record.cwe_id,
        vulnerability_title=record.vulnerability_title,
        target_file=record.target_file,
        status=record.status,  # type: ignore[arg-type]
        diff=diff,
        verification_report=report,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.post(
    "/remediation/draft",
    response_model=RemediationProposal,
    status_code=status.HTTP_201_CREATED,
    summary="Draft candidate AST patch proposal from dossier or finding",
)
async def draft_remediation_proposal(
    req: DraftRemediationRequest,
    db: AsyncSession = Depends(get_db),
):
    """Invokes Agent 10 to synthesize minimal syntax-safe AST patch and unified diff."""
    record = await service.draft_proposal(db, req)
    return _format_proposal(record)


@router.get(
    "/remediation/proposals",
    response_model=list[RemediationProposal],
    status_code=status.HTTP_200_OK,
    summary="Query stored remediation proposals with optional filtering",
)
async def list_proposals(
    status_filter: str | None = Query(default=None, alias="status", description="Filter by status (e.g. DRAFTED, VERIFIED, APPLIED)"),
    cwe_id: str | None = Query(default=None, description="Filter by CWE identifier (e.g. CWE-89)"),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve all remediation proposals, unified diffs, and verification reports."""
    records = await service.list_proposals(db, status=status_filter, cwe_id=cwe_id)
    return [_format_proposal(r) for r in records]


@router.get(
    "/remediation/proposals/{proposal_id}",
    response_model=RemediationProposal,
    status_code=status.HTTP_200_OK,
    summary="Retrieve single remediation proposal and full unified diff",
)
async def get_proposal(
    proposal_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get candidate patch proposal by ID."""
    record = await service.get_proposal(db, proposal_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation proposal '{proposal_id}' not found",
        )
    return _format_proposal(record)


@router.post(
    "/remediation/proposals/{proposal_id}/verify",
    response_model=RemediationProposal,
    status_code=status.HTTP_200_OK,
    summary="Execute Agent 11 sandbox verification and DAST exploit replay",
)
async def verify_remediation_proposal(
    proposal_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Validates AST syntax, tests invariants, and replays DAST exploit against patched code."""
    transport = ASGITransport(app=request.app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        record = await service.verify_proposal(db, proposal_id, client=client)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation proposal '{proposal_id}' not found",
        )
    return _format_proposal(record)


@router.post(
    "/remediation/proposals/{proposal_id}/apply",
    response_model=RemediationProposal,
    status_code=status.HTTP_200_OK,
    summary="Safely commit verified patch to disk codebase",
)
async def apply_remediation_proposal(
    proposal_id: str,
    dry_run: bool = Query(default=False, description="Preview application without mutating disk"),
    db: AsyncSession = Depends(get_db),
):
    """Writes patched code to disk, backups original, and updates finding status to REMEDIATED."""
    record = await service.apply_proposal(db, proposal_id, dry_run=dry_run)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation proposal '{proposal_id}' not found",
        )
    return _format_proposal(record)


@router.post(
    "/remediation/proposals/{proposal_id}/rollback",
    response_model=RemediationProposal,
    status_code=status.HTTP_200_OK,
    summary="Instantly roll back an applied patch restoring original code",
)
async def rollback_remediation_proposal(
    proposal_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Reverts patched file back to pre-remediation backup state."""
    record = await service.rollback_proposal(db, proposal_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation proposal '{proposal_id}' not found",
        )
    return _format_proposal(record)
