"""Remediation Service orchestrating patch drafting, sandbox verification, disk commit, and rollback."""

from pathlib import Path

from app.models.finding import SecurityFindingRecord
from app.models.remediation import RemediationProposalRecord
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.remediation.remediation_agent import RemediationAgent
from agents.verification.verification_agent import VerificationAgent
from security.schemas.correlation import TriangulatedDossier
from security.schemas.remediation import (
    ASTDiff,
    DraftRemediationRequest,
    RemediationProposal,
)
from services.evidence_correlation.correlation_service import EvidenceCorrelationService


class RemediationService:
    """Manages the complete automated remediation lifecycle from proposal creation to verified disk commit."""

    def __init__(
        self,
        remediation_agent: RemediationAgent | None = None,
        verification_agent: VerificationAgent | None = None,
        correlation_service: EvidenceCorrelationService | None = None,
    ):
        self.remediation_agent = remediation_agent or RemediationAgent()
        self.verification_agent = verification_agent or VerificationAgent()
        self.correlation_service = correlation_service or EvidenceCorrelationService()

    async def draft_proposal(
        self,
        db: AsyncSession,
        req: DraftRemediationRequest,
    ) -> RemediationProposalRecord:
        """Generate and persist a candidate remediation proposal."""
        proposal: RemediationProposal | None = None

        if req.target_file:
            proposal = self.remediation_agent.draft_patch(
                cwe_id=req.cwe_id or "CWE-89",
                target_file=req.target_file,
                dossier_id=req.dossier_id,
                finding_id=req.finding_id,
            )
        elif req.dossier_id or req.cwe_id:
            # Query dossier by CWE or id
            cwe = req.cwe_id or "CWE-89"
            dossier = await self.correlation_service.get_dossier_by_cwe(db, cwe)
            if dossier:
                proposal = self.remediation_agent.draft_patch_from_dossier(dossier)
            else:
                # Direct draft
                proposal = self.remediation_agent.draft_patch(
                    cwe_id=cwe,
                    dossier_id=req.dossier_id,
                )

        elif req.finding_id:
            stmt = select(SecurityFindingRecord).where(SecurityFindingRecord.id == req.finding_id)
            finding = (await db.execute(stmt)).scalars().first()
            if finding:
                proposal = self.remediation_agent.draft_patch_from_finding(finding)
            else:
                proposal = self.remediation_agent.draft_patch(
                    cwe_id="CWE-89",
                    finding_id=req.finding_id,
                )
        else:
            proposal = self.remediation_agent.draft_patch(
                cwe_id="CWE-89",
            )

        # Persist proposal record
        record = RemediationProposalRecord(
            id=proposal.proposal_id,
            dossier_id=proposal.dossier_id,
            finding_id=proposal.finding_id,
            cwe_id=proposal.cwe_id,
            vulnerability_title=proposal.vulnerability_title,
            target_file=proposal.target_file,
            status=proposal.status,
            strategy=proposal.diff.strategy,
            explanation=proposal.diff.explanation,
            line_start=proposal.diff.line_start,
            line_end=proposal.diff.line_end,
            original_code=proposal.diff.original_code,
            patched_code=proposal.diff.patched_code,
            unified_diff=proposal.diff.unified_diff,
            verification_report={},
        )
        db.add(record)
        await db.commit()
        await db.refresh(record)
        return record

    async def draft_from_dossier(
        self,
        db: AsyncSession,
        dossier: TriangulatedDossier,
    ) -> RemediationProposalRecord:
        """Convenience method drafting a proposal directly from a TriangulatedDossier."""
        proposal = self.remediation_agent.draft_patch_from_dossier(dossier)
        record = RemediationProposalRecord(
            id=proposal.proposal_id,
            dossier_id=proposal.dossier_id,
            cwe_id=proposal.cwe_id,
            vulnerability_title=proposal.vulnerability_title,
            target_file=proposal.target_file,
            status=proposal.status,
            strategy=proposal.diff.strategy,
            explanation=proposal.diff.explanation,
            line_start=proposal.diff.line_start,
            line_end=proposal.diff.line_end,
            original_code=proposal.diff.original_code,
            patched_code=proposal.diff.patched_code,
            unified_diff=proposal.diff.unified_diff,
            verification_report={},
        )
        db.add(record)
        await db.commit()
        await db.refresh(record)
        return record

    async def verify_proposal(
        self,
        db: AsyncSession,
        proposal_id: str,
        client: AsyncClient | None = None,
    ) -> RemediationProposalRecord | None:
        """Execute Agent 11 sandbox verification and exploit replay for target proposal."""
        stmt = select(RemediationProposalRecord).where(RemediationProposalRecord.id == proposal_id)
        record = (await db.execute(stmt)).scalars().first()
        if not record:
            return None

        # Reconstruct proposal schema
        proposal = RemediationProposal(
            proposal_id=record.id,
            dossier_id=record.dossier_id,
            finding_id=record.finding_id,
            cwe_id=record.cwe_id,
            vulnerability_title=record.vulnerability_title,
            target_file=record.target_file,
            status=record.status,  # type: ignore[arg-type]
            diff=ASTDiff(
                file_path=record.target_file,
                line_start=record.line_start,
                line_end=record.line_end,
                original_code=record.original_code,
                patched_code=record.patched_code,
                unified_diff=record.unified_diff,
                explanation=record.explanation,
                strategy=record.strategy,  # type: ignore[arg-type]
            ),
        )

        report = await self.verification_agent.verify_proposal(proposal, client=client)

        record.status = report.status
        record.verification_report = report.model_dump(mode="json")
        await db.commit()
        await db.refresh(record)
        return record

    async def apply_proposal(
        self,
        db: AsyncSession,
        proposal_id: str,
        dry_run: bool = False,
    ) -> RemediationProposalRecord | None:
        """Apply verified patch to codebase on disk and upgrade related finding status."""
        stmt = select(RemediationProposalRecord).where(RemediationProposalRecord.id == proposal_id)
        record = (await db.execute(stmt)).scalars().first()
        if not record:
            return None

        if not dry_run:
            target_path = Path(record.target_file)
            if not target_path.is_file():
                target_path = Path.cwd() / record.target_file

            if target_path.is_file():
                # Write patched code
                target_path.write_text(record.patched_code, encoding="utf-8")

        record.status = "APPLIED"

        # Upgrade associated finding status if present
        if record.finding_id:
            f_stmt = select(SecurityFindingRecord).where(SecurityFindingRecord.id == record.finding_id)
            finding = (await db.execute(f_stmt)).scalars().first()
            if finding:
                finding.status = "REMEDIATED"

        await db.commit()
        await db.refresh(record)

        return record

    async def rollback_proposal(
        self,
        db: AsyncSession,
        proposal_id: str,
    ) -> RemediationProposalRecord | None:
        """Roll back an applied patch by restoring original code from proposal record backup."""
        stmt = select(RemediationProposalRecord).where(RemediationProposalRecord.id == proposal_id)
        record = (await db.execute(stmt)).scalars().first()
        if not record:
            return None

        target_path = Path(record.target_file)
        if not target_path.is_file():
            target_path = Path.cwd() / record.target_file

        if target_path.is_file() and record.original_code:
            target_path.write_text(record.original_code, encoding="utf-8")

        record.status = "ROLLED_BACK"

        # Restore associated finding status
        if record.finding_id:
            f_stmt = select(SecurityFindingRecord).where(SecurityFindingRecord.id == record.finding_id)
            finding = (await db.execute(f_stmt)).scalars().first()
            if finding:
                finding.status = "OPEN"

        await db.commit()
        await db.refresh(record)
        return record

    async def list_proposals(
        self,
        db: AsyncSession,
        status: str | None = None,
        cwe_id: str | None = None,
    ) -> list[RemediationProposalRecord]:
        """Query stored remediation proposals with optional status or CWE filtering."""
        stmt = select(RemediationProposalRecord)
        if status:
            stmt = stmt.where(RemediationProposalRecord.status == status.upper())
        if cwe_id:
            stmt = stmt.where(RemediationProposalRecord.cwe_id == cwe_id.upper())

        res = await db.execute(stmt.order_by(RemediationProposalRecord.created_at.desc()))
        return list(res.scalars().all())

    async def get_proposal(
        self,
        db: AsyncSession,
        proposal_id: str,
    ) -> RemediationProposalRecord | None:
        """Retrieve single proposal by ID."""
        stmt = select(RemediationProposalRecord).where(RemediationProposalRecord.id == proposal_id)
        return (await db.execute(stmt)).scalars().first()
