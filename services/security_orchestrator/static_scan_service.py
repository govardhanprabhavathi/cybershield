from datetime import UTC, datetime

from app.core.config import Settings, get_settings
from app.models.finding import SecurityFindingRecord
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.application_mapper.mapper_agent import ApplicationMapperAgent
from agents.code_security.code_security_agent import CodeSecurityAgent
from agents.configuration_security.config_agent import ConfigurationSecurityAgent
from agents.dependency_security.dependency_agent import DependencySecurityAgent
from agents.secret_security.secret_agent import SecretSecurityAgent
from security.schemas.findings import SecurityFinding, StaticScanReport


class StaticScanService:
    """Pre-Deployment Security Analysis Orchestrator running Agents 1, 2, 4, 5, and 6."""

    @staticmethod
    async def run_full_scan(
        db: AsyncSession,
        app: FastAPI,
        settings: Settings | None = None,
        persist_to_db: bool = True,
    ) -> StaticScanReport:
        cfg = settings or get_settings()

        # Agent 1: Application Mapper
        mapper_agent = ApplicationMapperAgent(app=app)
        app_map = mapper_agent.scan()

        # Agent 2: Code Security
        code_agent = CodeSecurityAgent(target_dir="apps/ecommerce-backend/app")
        code_findings = code_agent.scan()

        # Agent 4: Dependency Security
        dep_agent = DependencySecurityAgent(manifest_path="pyproject.toml")
        dep_findings = dep_agent.scan()

        # Agent 5: Secret Security
        secret_agent = SecretSecurityAgent(target_dir="apps/ecommerce-backend")
        secret_findings = secret_agent.scan()

        # Agent 6: Configuration Security
        config_agent = ConfigurationSecurityAgent(settings=cfg)
        config_findings = config_agent.scan()

        # Aggregate and deduplicate findings
        all_findings: list[SecurityFinding] = (
            code_findings + dep_findings + secret_findings + config_findings
        )

        seen_keys = set()
        deduped_findings: list[SecurityFinding] = []
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}

        for finding in all_findings:
            key = (finding.category, finding.file_path, finding.line_number, finding.endpoint)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduped_findings.append(finding)

            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1

        # Persist findings to database
        if persist_to_db:
            for f in deduped_findings:
                # Check if identical finding already exists to prevent duplication across runs
                existing = await db.execute(
                    select(SecurityFindingRecord).where(
                        SecurityFindingRecord.category == f.category,
                        SecurityFindingRecord.file_path == f.file_path,
                        SecurityFindingRecord.line_number == f.line_number,
                    )
                )
                if not existing.scalar_one_or_none():
                    record = SecurityFindingRecord(
                        id=f.finding_id,
                        agent_source=f.agent_source,
                        category=f.category,
                        cwe_id=f.cwe_id,
                        owasp_category=f.owasp_category,
                        severity=f.severity,
                        confidence=f.confidence,
                        title=f.title,
                        description=f.description,
                        file_path=f.file_path,
                        line_number=f.line_number,
                        endpoint=f.endpoint,
                        method=f.method,
                        parameter=f.parameter,
                        raw_evidence=f.raw_evidence,
                        remediation_guidance=f.remediation_guidance,
                        status=f.status,
                        created_at=f.created_at,
                    )
                    db.add(record)
            await db.commit()

        return StaticScanReport(
            timestamp=datetime.now(UTC),
            total_findings=len(deduped_findings),
            findings_by_severity=by_severity,
            findings_by_category=by_category,
            findings=deduped_findings,
            application_map=app_map,
        )
