from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from app.models.finding import SecurityFindingRecord
from app.models.incident import RuntimeIncidentRecord

from security.correlation_engine.triangulator import EvidenceTriangulator
from security.schemas.correlation import EvidenceArtifact, TriangulatedDossier
from security.schemas.incident import RuntimeIncident


class EvidenceCorrelationAgent:
    """Correlates static AST code flaws, dynamic DAST probes, and runtime telemetry incidents."""

    def __init__(self):
        self.triangulator = EvidenceTriangulator()

    def correlate_incident(
        self,
        incident: RuntimeIncident,
        findings: list[SecurityFindingRecord],
    ) -> tuple[SecurityFindingRecord | None, TriangulatedDossier | None]:
        """Correlate a single live runtime incident against existing stored vulnerability findings."""
        norm_incident_ep = self.triangulator.normalize_endpoint(incident.endpoint)

        matched_finding: SecurityFindingRecord | None = None
        for f in findings:
            norm_finding_ep = self.triangulator.normalize_endpoint(f.endpoint)

            # Match criteria: same CWE ID and matching normalized endpoint (or matching CWE if endpoint missing)
            if (
                f.cwe_id
                and incident.cwe_id
                and f.cwe_id == incident.cwe_id
                and (not f.endpoint or norm_finding_ep == norm_incident_ep)
            ):
                matched_finding = f
                break

        if not matched_finding:
            # Build runtime-only dossier if no pre-deployment finding exists
            dossier = self.triangulator.build_dossier(
                cwe_id=incident.cwe_id,
                endpoint=norm_incident_ep,
                vulnerability_title=f"Runtime Detected {incident.attack_type}",
                owasp_category="Runtime Threat",
                severity=incident.severity,
                method=incident.method,
                remediation_guidance="Apply input sanitization and authorization gates for target endpoint.",
                runtime_incidents=[incident],
            )
            return None, dossier

        # Correlated! Elevate status to ACTIVELY_EXPLOITED and confidence to >= 0.99
        matched_finding.status = "ACTIVELY_EXPLOITED"
        matched_finding.confidence = max(matched_finding.confidence, 0.99)

        # Attach correlated incident metadata to finding's evidence
        evidence_dict = dict(matched_finding.raw_evidence or {})
        incidents_list = evidence_dict.get("correlated_runtime_incidents", [])
        if incident.incident_id not in incidents_list:
            incidents_list.append(incident.incident_id)
        evidence_dict["correlated_runtime_incidents"] = incidents_list
        evidence_dict["last_exploiting_session_id"] = incident.session_id
        matched_finding.raw_evidence = evidence_dict

        # Build synthesized dossier
        pillar = "DAST" if "dast" in matched_finding.agent_source.lower() else "SAST"
        detected_time = matched_finding.created_at or datetime.now(UTC)
        artifacts = [
            EvidenceArtifact(
                pillar=pillar,
                source_agent=matched_finding.agent_source,
                detected_at=detected_time,
                confidence=matched_finding.confidence,
                summary=matched_finding.title,
                evidence_data=matched_finding.raw_evidence or {},
            )
        ]
        if matched_finding.raw_evidence and "dast_confirmation" in matched_finding.raw_evidence and pillar != "DAST":
            artifacts.append(
                EvidenceArtifact(
                    pillar="DAST",
                    source_agent="api_security_dast",
                    detected_at=detected_time,
                    confidence=matched_finding.confidence,
                    summary=f"Dynamic Probe Confirmed: {matched_finding.title}",
                    evidence_data=matched_finding.raw_evidence.get("dast_confirmation", {}),
                )
            )

        dossier = self.triangulator.build_dossier(
            cwe_id=matched_finding.cwe_id,
            endpoint=matched_finding.endpoint or norm_incident_ep,
            vulnerability_title=matched_finding.title,
            owasp_category=matched_finding.owasp_category,
            severity=matched_finding.severity,
            method=matched_finding.method or incident.method,
            file_path=matched_finding.file_path,
            line_number=matched_finding.line_number,
            remediation_guidance=matched_finding.remediation_guidance,
            artifacts=artifacts,
            runtime_incidents=[incident],
        )

        return matched_finding, dossier

    def correlate_repository(
        self,
        findings: list[SecurityFindingRecord],
        incidents: list[RuntimeIncidentRecord],
    ) -> list[TriangulatedDossier]:
        """Execute full platform multi-pillar correlation across all stored findings and incidents."""
        # Group by (normalized_endpoint, cwe_id)
        clusters: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {
                "findings": [],
                "incidents": [],
                "title": "",
                "owasp": "",
                "severity": "MEDIUM",
                "method": "GET",
                "file_path": None,
                "line_number": None,
                "remediation": "",
            }
        )

        # 1. Cluster findings (SAST & DAST)
        for f in findings:
            norm_ep = self.triangulator.normalize_endpoint(f.endpoint)
            key = (norm_ep, f.cwe_id)
            c = clusters[key]
            c["findings"].append(f)
            c["title"] = c["title"] or f.title
            c["owasp"] = c["owasp"] or f.owasp_category
            c["severity"] = f.severity if f.severity in ("CRITICAL", "HIGH") else c["severity"]
            c["method"] = f.method or c["method"]
            c["file_path"] = c["file_path"] or f.file_path
            c["line_number"] = c["line_number"] or f.line_number
            c["remediation"] = c["remediation"] or f.remediation_guidance

        # 2. Cluster incidents (Runtime)
        for inc in incidents:
            norm_ep = self.triangulator.normalize_endpoint(inc.endpoint)
            key = (norm_ep, inc.cwe_id)
            c = clusters[key]
            c["incidents"].append(inc)
            if not c["title"]:
                c["title"] = f"Runtime {inc.attack_type} on {norm_ep}"
                c["owasp"] = "Runtime Attack"
                c["severity"] = inc.severity
                c["method"] = inc.method
                c["remediation"] = "Apply validation, escaping, and access controls."

        # 3. Build dossiers for each cluster
        dossiers: list[TriangulatedDossier] = []
        for (ep, cwe), data in clusters.items():
            artifacts: list[EvidenceArtifact] = []

            for f in data["findings"]:
                detected_time = f.created_at or datetime.now(UTC)
                evidence = f.raw_evidence or {}
                is_dast = "dast" in f.agent_source.lower() or "probe" in f.agent_source.lower()
                pillar = "DAST" if is_dast else "SAST"
                artifacts.append(
                    EvidenceArtifact(
                        pillar=pillar,
                        source_agent=f.agent_source,
                        detected_at=detected_time,
                        confidence=f.confidence,
                        summary=f.title,
                        evidence_data=evidence,
                    )
                )
                if not is_dast and "dast_confirmation" in evidence:
                    artifacts.append(
                        EvidenceArtifact(
                            pillar="DAST",
                            source_agent="api_security_dast",
                            detected_at=detected_time,
                            confidence=f.confidence,
                            summary=f"Dynamic Probe Confirmed: {f.title}",
                            evidence_data=evidence.get("dast_confirmation", {}),
                        )
                    )

            dossier = self.triangulator.build_dossier(
                cwe_id=cwe,
                endpoint=ep,
                vulnerability_title=data["title"],
                owasp_category=data["owasp"],
                severity=data["severity"],
                method=data["method"],
                file_path=data["file_path"],
                line_number=data["line_number"],
                remediation_guidance=data["remediation"],
                artifacts=artifacts,
                runtime_incidents=data["incidents"],
            )
            dossiers.append(dossier)

        # Sort dossiers by composite confidence descending, then severity
        return sorted(dossiers, key=lambda d: (d.composite_confidence, len(d.pillars_present)), reverse=True)
