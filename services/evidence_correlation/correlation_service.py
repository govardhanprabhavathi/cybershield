"""Evidence Correlation Service coordinating multi-pillar triangulation, dossier persistence, and reporting."""

from collections import Counter
from datetime import UTC, datetime

from app.models.finding import SecurityFindingRecord
from app.models.incident import RuntimeIncidentRecord
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.evidence_correlation.correlation_agent import EvidenceCorrelationAgent
from security.schemas.correlation import TriangulatedDossier, TriangulationReport
from security.schemas.incident import RuntimeIncident


class EvidenceCorrelationService:
    """Orchestrates database queries across static/dynamic findings and live incidents to synthesize evidence dossiers."""

    def __init__(self, agent: EvidenceCorrelationAgent | None = None):
        self.agent = agent or EvidenceCorrelationAgent()

    async def triangulate_all(self, db: AsyncSession) -> TriangulationReport:
        """Run global triangulation across all findings and runtime incidents stored in the platform."""
        findings_res = await db.execute(select(SecurityFindingRecord))
        findings = list(findings_res.scalars().all())

        incidents_res = await db.execute(select(RuntimeIncidentRecord))
        incidents = list(incidents_res.scalars().all())

        dossiers = self.agent.correlate_repository(findings=findings, incidents=incidents)

        # Commit any finding status / confidence upgrades
        if findings:
            await db.commit()

        tier_counts = Counter(d.triangulation_tier for d in dossiers)
        status_counts = Counter(d.exploit_status for d in dossiers)
        fully_triangulated = sum(1 for d in dossiers if d.triangulation_tier == "FULL_TRIANGULATION")
        actively_exploited = sum(1 for d in dossiers if d.exploit_status == "ACTIVELY_EXPLOITED")

        return TriangulationReport(
            generated_at=datetime.now(UTC),
            total_dossiers=len(dossiers),
            fully_triangulated_count=fully_triangulated,
            actively_exploited_count=actively_exploited,
            dossiers_by_tier=dict(tier_counts),
            dossiers_by_status=dict(status_counts),
            dossiers=dossiers,
        )

    async def get_dossier_by_cwe(self, db: AsyncSession, cwe_id: str) -> TriangulatedDossier | None:
        """Retrieve the primary triangulated dossier for a specified CWE ID (e.g., CWE-89, CWE-284)."""
        report = await self.triangulate_all(db)
        target = cwe_id.upper().strip()
        matching = [d for d in report.dossiers if d.cwe_id.upper() == target]
        return matching[0] if matching else None

    async def list_actively_exploited(self, db: AsyncSession) -> list[TriangulatedDossier]:
        """Query all vulnerabilities confirmed to be actively targeted or exploited by live adversary sessions."""
        report = await self.triangulate_all(db)
        return [d for d in report.dossiers if d.exploit_status == "ACTIVELY_EXPLOITED"]

    async def correlate_incident(
        self, db: AsyncSession, incident: RuntimeIncident
    ) -> TriangulatedDossier | None:
        """Correlate a single live incident on-the-fly and elevate matching finding records."""
        findings_res = await db.execute(select(SecurityFindingRecord))
        findings = list(findings_res.scalars().all())

        matched_record, dossier = self.agent.correlate_incident(incident, findings)
        if matched_record:
            await db.commit()

        return dossier
