"""Evidence correlation and multi-pillar triangulation REST API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from security.schemas.correlation import TriangulatedDossier, TriangulationReport
from services.evidence_correlation.correlation_service import EvidenceCorrelationService

router = APIRouter()
service = EvidenceCorrelationService()


@router.post(
    "/correlation/triangulate",
    response_model=TriangulationReport,
    status_code=status.HTTP_200_OK,
    summary="Execute multi-pillar SAST-DAST-Runtime triangulation across all findings",
)
async def run_triangulation(db: AsyncSession = Depends(get_db)):
    """Cross-references static AST code flaws, dynamic DAST probes, and runtime incident telemetry."""
    return await service.triangulate_all(db)


@router.get(
    "/correlation/dossiers",
    response_model=list[TriangulatedDossier],
    status_code=status.HTTP_200_OK,
    summary="Query unified vulnerability evidence dossiers with optional filtering",
)
async def list_vulnerability_dossiers(
    tier: str | None = Query(default=None, description="Filter by triangulation tier (e.g. FULL_TRIANGULATION)"),
    exploit_status: str | None = Query(default=None, description="Filter by exploit status (e.g. ACTIVELY_EXPLOITED)"),
    cwe_id: str | None = Query(default=None, description="Filter by CWE identifier (e.g. CWE-89)"),
    db: AsyncSession = Depends(get_db),
):
    """Returns synthesized evidence dossiers capturing code locations, probe traces, and live attacker sessions."""
    report = await service.triangulate_all(db)
    dossiers = report.dossiers

    if tier:
        dossiers = [d for d in dossiers if d.triangulation_tier.upper() == tier.upper()]
    if exploit_status:
        dossiers = [d for d in dossiers if d.exploit_status.upper() == exploit_status.upper()]
    if cwe_id:
        dossiers = [d for d in dossiers if d.cwe_id.upper() == cwe_id.upper()]

    return dossiers


@router.get(
    "/correlation/actively-exploited",
    response_model=list[TriangulatedDossier],
    status_code=status.HTTP_200_OK,
    summary="Query vulnerabilities currently confirmed under active cyber exploitation",
)
async def list_actively_exploited_vulnerabilities(db: AsyncSession = Depends(get_db)):
    """Immediate dashboard query identifying all code flaws actively undergoing live exploitation."""
    return await service.list_actively_exploited(db)


@router.get(
    "/correlation/dossiers/{cwe_id}",
    response_model=TriangulatedDossier,
    status_code=status.HTTP_200_OK,
    summary="Retrieve primary triangulated evidence dossier for a specific CWE",
)
async def get_cwe_dossier(cwe_id: str, db: AsyncSession = Depends(get_db)):
    """Returns detailed cross-pillar evidence dossier for a specific weakness."""
    dossier = await service.get_dossier_by_cwe(db, cwe_id)
    if not dossier:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No evidence dossier discovered for CWE {cwe_id}",
        )
    return dossier
