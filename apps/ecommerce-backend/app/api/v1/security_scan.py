from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import PlainTextResponse
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.api_security.api_security_agent import APISecurityAgent
from app.core.database import get_db
from app.models.finding import SecurityFindingRecord
from security.schemas.findings import (
    ApplicationMap,
    DynamicScanReport,
    SecurityFinding,
    StaticScanReport,
)
from services.security_orchestrator.dynamic_scan_service import DynamicScanService
from services.security_orchestrator.static_scan_service import StaticScanService

router = APIRouter()


@router.post(
    "/scan/static",
    response_model=StaticScanReport,
    status_code=status.HTTP_200_OK,
    summary="Trigger Pre-Deployment Static Security Analysis (Agents 1, 2, 4, 5, 6)",
)
async def trigger_static_scan(
    request: Request,
    persist: bool = Query(default=True, description="Persist findings to security_findings table"),
    db: AsyncSession = Depends(get_db),
):
    """Executes the pre-deployment security pipeline across application mapper, code, dependency, secret, and configuration agents."""
    report = await StaticScanService.run_full_scan(
        db=db,
        app=request.app,
        persist_to_db=persist,
    )
    return report


@router.get(
    "/findings",
    response_model=list[SecurityFinding],
    status_code=status.HTTP_200_OK,
    summary="List stored security findings with optional severity and category filters",
)
async def list_security_findings(
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    endpoint: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    query = select(SecurityFindingRecord)
    if category:
        query = query.where(SecurityFindingRecord.category == category)
    if severity:
        query = query.where(SecurityFindingRecord.severity == severity)
    if endpoint:
        query = query.where(SecurityFindingRecord.endpoint == endpoint)

    query = query.order_by(SecurityFindingRecord.created_at.desc())
    result = await db.execute(query)
    records = result.scalars().all()

    findings_out = []
    for r in records:
        findings_out.append(
            SecurityFinding(
                finding_id=r.id,
                agent_source=r.agent_source,
                category=r.category,
                cwe_id=r.cwe_id,
                owasp_category=r.owasp_category,
                severity=r.severity,
                confidence=r.confidence,
                title=r.title,
                description=r.description,
                file_path=r.file_path,
                line_number=r.line_number,
                endpoint=r.endpoint,
                method=r.method,
                parameter=r.parameter,
                raw_evidence=r.raw_evidence,
                remediation_guidance=r.remediation_guidance,
                status=r.status,
                created_at=r.created_at,
            )
        )

    return findings_out


@router.get(
    "/map",
    response_model=ApplicationMap,
    status_code=status.HTTP_200_OK,
    summary="Retrieve current application route, authorization, and model map",
)
async def get_application_map(request: Request):
    from agents.application_mapper.mapper_agent import ApplicationMapperAgent

    mapper = ApplicationMapperAgent(app=request.app)
    return mapper.scan()


@router.post(
    "/scan/dynamic",
    response_model=DynamicScanReport,
    status_code=status.HTTP_200_OK,
    summary="Trigger Pre-Deployment Dynamic Security Analysis (Agent 3 DAST Probing)",
)
async def trigger_dynamic_scan(
    request: Request,
    persist: bool = Query(default=True, description="Persist and correlate dynamic findings with SAST"),
    db: AsyncSession = Depends(get_db),
):
    """Executes dynamic API vulnerability probes (BOLA, SQLi, Resource Consumption, Business Flows) and correlates with SAST."""
    transport = ASGITransport(app=request.app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        report = await DynamicScanService.run_dynamic_scan(
            db=db,
            client=client,
            app=request.app,
            persist_to_db=persist,
        )
    return report


@router.get(
    "/scan/dynamic/zap-config",
    response_class=PlainTextResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate OWASP ZAP Automation Framework configuration plan",
)
async def get_zap_config(
    target_url: str = Query(default="http://localhost:8000", description="Base URL of target API"),
):
    agent = APISecurityAgent(client=None)
    return PlainTextResponse(agent.generate_zap_automation_plan(target_url=target_url))


@router.get(
    "/findings/confirmed",
    response_model=list[SecurityFinding],
    status_code=status.HTTP_200_OK,
    summary="List security findings dynamically confirmed by DAST probing",
)
async def list_confirmed_findings(db: AsyncSession = Depends(get_db)):
    query = (
        select(SecurityFindingRecord)
        .where(SecurityFindingRecord.status == "CONFIRMED")
        .order_by(SecurityFindingRecord.created_at.desc())
    )
    result = await db.execute(query)
    records = result.scalars().all()

    return [
        SecurityFinding(
            finding_id=r.id,
            agent_source=r.agent_source,
            category=r.category,
            cwe_id=r.cwe_id,
            owasp_category=r.owasp_category,
            severity=r.severity,
            confidence=r.confidence,
            title=r.title,
            description=r.description,
            file_path=r.file_path,
            line_number=r.line_number,
            endpoint=r.endpoint,
            method=r.method,
            parameter=r.parameter,
            raw_evidence=r.raw_evidence,
            remediation_guidance=r.remediation_guidance,
            status=r.status,
            created_at=r.created_at,
        )
        for r in records
    ]

