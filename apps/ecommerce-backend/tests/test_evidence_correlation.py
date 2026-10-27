"""Test suite for Phase 8: Evidence Correlation & SAST-DAST-Runtime Triangulation Engine."""

import pytest
from app.core.database import get_session_maker
from app.models.finding import SecurityFindingRecord
from app.models.incident import RuntimeIncidentRecord
from httpx import AsyncClient

from agents.evidence_correlation.correlation_agent import EvidenceCorrelationAgent
from security.correlation_engine.triangulator import EvidenceTriangulator
from security.schemas.incident import RuntimeIncident
from services.evidence_correlation.correlation_service import EvidenceCorrelationService


def test_endpoint_normalization_and_cwe_matching():
    """Verify endpoint normalization removes query parameters and handles dynamic path variables."""
    triangulator = EvidenceTriangulator()

    # Dynamic order parameter
    assert triangulator.normalize_endpoint("/api/v1/orders/1001") == "/api/v1/orders/{order_id}"
    assert triangulator.normalize_endpoint("/api/v1/orders/ORD-98765") == "/api/v1/orders/{order_id}"
    # Preserves non-dynamic sub-paths
    assert triangulator.normalize_endpoint("/api/v1/orders/checkout") == "/api/v1/orders/checkout"

    # Dynamic product UUID
    assert (
        triangulator.normalize_endpoint("/api/v1/products/12345678-abcd-1234-abcd-1234567890ab")
        == "/api/v1/products/{id}"
    )

    # Strips query parameters
    assert triangulator.normalize_endpoint("/api/v1/products?search=laptop&sort=desc") == "/api/v1/products"
    assert triangulator.normalize_endpoint("/api/v1/products/?limit=10") == "/api/v1/products"

    # Empty and None handling
    assert triangulator.normalize_endpoint("") == ""
    assert triangulator.normalize_endpoint(None) == ""


def test_mathematical_composite_confidence_escalation():
    """Validate mathematical Bayesian confidence calculation and tier progression."""
    triangulator = EvidenceTriangulator()

    # 0 Pillars: Empty
    conf, tier, status = triangulator.calculate_composite_confidence(set(), {})
    assert conf == 0.0
    assert tier == "SAST_ONLY"
    assert status == "THEORETICAL"

    # 1 Pillar: SAST only
    conf, tier, status = triangulator.calculate_composite_confidence({"SAST"}, {"SAST": 0.80})
    assert conf == 0.80
    assert tier == "SAST_ONLY"
    assert status == "THEORETICAL"

    # 1 Pillar: DAST only
    conf, tier, status = triangulator.calculate_composite_confidence({"DAST"}, {"DAST": 0.90})
    assert conf == 0.90
    assert tier == "DAST_ONLY"
    assert status == "CONFIRMED_EXPLOITABLE"

    # 1 Pillar: Runtime only
    conf, tier, status = triangulator.calculate_composite_confidence({"RUNTIME"}, {"RUNTIME": 0.95})
    assert conf == 0.95
    assert tier == "RUNTIME_ONLY"
    assert status == "ACTIVELY_TARGETED"

    # 2 Pillars: SAST + DAST
    conf, tier, status = triangulator.calculate_composite_confidence(
        {"SAST", "DAST"}, {"SAST": 0.80, "DAST": 0.90}
    )
    assert conf >= 0.95
    assert tier == "SAST_DAST"
    assert status == "CONFIRMED_EXPLOITABLE"

    # 2 Pillars: SAST + Runtime
    conf, tier, status = triangulator.calculate_composite_confidence(
        {"SAST", "RUNTIME"}, {"SAST": 0.80, "RUNTIME": 0.95}
    )
    assert conf >= 0.96
    assert tier == "SAST_RUNTIME"
    assert status == "ACTIVELY_TARGETED"

    # 2 Pillars: DAST + Runtime
    conf, tier, status = triangulator.calculate_composite_confidence(
        {"DAST", "RUNTIME"}, {"DAST": 0.90, "RUNTIME": 0.95}
    )
    assert conf >= 0.98
    assert tier == "DAST_RUNTIME"
    assert status == "ACTIVELY_EXPLOITED"

    # 3 Pillars: Full Triangulation (SAST + DAST + Runtime)
    conf, tier, status = triangulator.calculate_composite_confidence(
        {"SAST", "DAST", "RUNTIME"}, {"SAST": 0.80, "DAST": 0.90, "RUNTIME": 0.95}
    )
    assert conf >= 0.99
    assert tier == "FULL_TRIANGULATION"
    assert status == "ACTIVELY_EXPLOITED"


def test_sast_dast_runtime_triangulation_flow():
    """Verify single live incident correlation escalates stored finding to ACTIVELY_EXPLOITED."""
    agent = EvidenceCorrelationAgent()

    finding = SecurityFindingRecord(
        agent_source="code_security",
        category="SQL_INJECTION",
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
        severity="HIGH",
        confidence=0.85,
        title="Potential SQL Injection in Product Search",
        description="Dynamic string formatting into raw SQL clause.",
        file_path="apps/ecommerce-backend/app/services/product_service.py",
        line_number=42,
        endpoint="/api/v1/products",
        method="GET",
        parameter="search",
        raw_evidence={"vulnerable_code": "SELECT * FROM products WHERE name LIKE '%...%'"},
        status="OPEN",
    )

    incident = RuntimeIncident(
        session_id="adversary_session_101",
        attack_type="SQL_INJECTION",
        severity="HIGH",
        confidence=0.98,
        cwe_id="CWE-89",
        endpoint="/api/v1/products?search=' OR '1'='1--",
        method="GET",
        trigger_event_id="evt-sql-101",
    )

    matched_record, dossier = agent.correlate_incident(incident, [finding])

    assert matched_record is not None
    assert matched_record.status == "ACTIVELY_EXPLOITED"
    assert matched_record.confidence >= 0.99
    assert incident.incident_id in matched_record.raw_evidence["correlated_runtime_incidents"]
    assert matched_record.raw_evidence["last_exploiting_session_id"] == "adversary_session_101"

    assert dossier is not None
    assert dossier.cwe_id == "CWE-89"
    assert dossier.triangulation_tier == "SAST_RUNTIME"
    assert dossier.exploit_status == "ACTIVELY_TARGETED"
    assert dossier.composite_confidence >= 0.96
    assert "adversary_session_101" in dossier.adversary_session_ids


def test_evidence_dossier_contains_code_and_http_artifacts():
    """Verify repository correlation synthesizes full dossiers with code locations, probes, and telemetry."""
    agent = EvidenceCorrelationAgent()

    sast_finding = SecurityFindingRecord(
        agent_source="code_security",
        category="SQL_INJECTION",
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
        severity="HIGH",
        confidence=0.85,
        title="SQL Injection Code Flaw",
        file_path="apps/ecommerce-backend/app/services/product_service.py",
        line_number=42,
        endpoint="/api/v1/products",
        method="GET",
        raw_evidence={"file": "product_service.py", "line": 42},
    )

    dast_finding = SecurityFindingRecord(
        agent_source="api_security_dast",
        category="SQL_INJECTION",
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
        severity="HIGH",
        confidence=0.98,
        title="SQL Injection Dynamic Probe Confirmed",
        file_path="apps/ecommerce-backend/app/services/product_service.py",
        line_number=42,
        endpoint="/api/v1/products",
        method="GET",
        raw_evidence={"probe": "SQLI_PROBE_VECTORS", "injected_payload": "' OR '1'='1--"},
    )

    runtime_record = RuntimeIncidentRecord(
        session_id="adversary_session_202",
        attack_type="SQL_INJECTION",
        severity="HIGH",
        confidence=0.99,
        cwe_id="CWE-89",
        endpoint="/api/v1/products?search=exploit_payload",
        method="GET",
        trigger_event_id="evt-sql-202",
        raw_evidence={"matched_pattern": "SQLI_OR_TAUTOLOGY"},
    )

    dossiers = agent.correlate_repository(
        findings=[sast_finding, dast_finding],
        incidents=[runtime_record],
    )

    assert len(dossiers) == 1
    dossier = dossiers[0]

    assert dossier.cwe_id == "CWE-89"
    assert dossier.triangulation_tier == "FULL_TRIANGULATION"
    assert dossier.exploit_status == "ACTIVELY_EXPLOITED"
    assert dossier.composite_confidence >= 0.99
    assert dossier.file_path == "apps/ecommerce-backend/app/services/product_service.py"
    assert dossier.line_number == 42
    assert dossier.pillars_present == ["DAST", "RUNTIME", "SAST"]
    assert dossier.adversary_session_ids == ["adversary_session_202"]
    assert len(dossier.evidence_artifacts) == 2
    assert len(dossier.timeline) == 3


@pytest.mark.asyncio
async def test_correlation_service_database_methods():
    """Verify EvidenceCorrelationService queries the DB, updates finding records, and compiles reports."""
    session_maker = await get_session_maker()
    async with session_maker() as session:
        # Seed finding and incident
        finding = SecurityFindingRecord(
            agent_source="code_security",
            category="SQL_INJECTION",
            cwe_id="CWE-89",
            owasp_category="A03:2021-Injection",
            severity="HIGH",
            confidence=0.80,
            title="Static SQL Injection Finding",
            endpoint="/api/v1/products",
            method="GET",
        )
        incident = RuntimeIncidentRecord(
            session_id="session_db_test_99",
            attack_type="SQL_INJECTION",
            severity="HIGH",
            confidence=0.95,
            cwe_id="CWE-89",
            endpoint="/api/v1/products",
            method="GET",
            trigger_event_id="evt-db-99",
        )
        session.add(finding)
        session.add(incident)
        await session.commit()

        service = EvidenceCorrelationService()
        report = await service.triangulate_all(session)

        assert report.total_dossiers >= 1
        assert "SAST_RUNTIME" in report.dossiers_by_tier or "FULL_TRIANGULATION" in report.dossiers_by_tier

        # Test single CWE query
        cwe_dossier = await service.get_dossier_by_cwe(session, "CWE-89")
        assert cwe_dossier is not None
        assert cwe_dossier.cwe_id == "CWE-89"

        # Non-existent CWE query
        none_dossier = await service.get_dossier_by_cwe(session, "CWE-99999")
        assert none_dossier is None


@pytest.mark.asyncio
async def test_correlation_rest_api_endpoints(async_client: AsyncClient):
    """End-to-end integration test verifying full SAST-DAST-Runtime triangulation via REST API."""
    # 1. Run static scan to populate baseline SAST findings
    static_res = await async_client.post("/security/v1/scan/static?persist=true")
    assert static_res.status_code == 200

    # 2. Run dynamic scan to populate confirmed DAST findings
    dynamic_res = await async_client.post("/security/v1/scan/dynamic?persist=true")
    assert dynamic_res.status_code == 200

    # 3. Simulate runtime attack request that triggers middleware and detection worker
    sqli_url = "/api/v1/products?search=payload' OR '1'='1--"
    attack_res = await async_client.get(sqli_url)
    assert attack_res.status_code in (200, 500)

    # Process telemetry batch with Agent 7 to generate and persist runtime incident
    batch_res = await async_client.post("/security/v1/detection/process-batch?count=50")
    assert batch_res.status_code == 200

    # 4. Execute multi-pillar triangulation API
    triangulate_res = await async_client.post("/security/v1/correlation/triangulate")
    assert triangulate_res.status_code == 200
    report = triangulate_res.json()

    assert report["total_dossiers"] >= 2
    assert "dossiers" in report
    assert report["fully_triangulated_count"] >= 1
    assert report["actively_exploited_count"] >= 1

    # 5. Query dossiers list with filtering
    dossiers_res = await async_client.get("/security/v1/correlation/dossiers")
    assert dossiers_res.status_code == 200
    all_dossiers = dossiers_res.json()
    assert len(all_dossiers) >= 2

    cwe_filtered = await async_client.get("/security/v1/correlation/dossiers?cwe_id=CWE-89")
    assert cwe_filtered.status_code == 200
    assert len(cwe_filtered.json()) >= 1
    assert cwe_filtered.json()[0]["cwe_id"] == "CWE-89"

    # 6. Query actively exploited vulnerabilities
    actively_res = await async_client.get("/security/v1/correlation/actively-exploited")
    assert actively_res.status_code == 200
    exploited_list = actively_res.json()
    assert len(exploited_list) >= 1
    for d in exploited_list:
        assert d["exploit_status"] == "ACTIVELY_EXPLOITED"

    # 7. Query specific CWE dossier
    cwe89_res = await async_client.get("/security/v1/correlation/dossiers/CWE-89")
    assert cwe89_res.status_code == 200
    dossier_cwe89 = cwe89_res.json()
    assert dossier_cwe89["cwe_id"] == "CWE-89"
    assert dossier_cwe89["triangulation_tier"] == "FULL_TRIANGULATION"
    assert dossier_cwe89["composite_confidence"] >= 0.99
    assert "SAST" in dossier_cwe89["pillars_present"]
    assert "DAST" in dossier_cwe89["pillars_present"]
    assert "RUNTIME" in dossier_cwe89["pillars_present"]
    assert len(dossier_cwe89["timeline"]) >= 3

    # 8. Query nonexistent CWE returns 404
    cwe_missing_res = await async_client.get("/security/v1/correlation/dossiers/CWE-9999")
    assert cwe_missing_res.status_code == 404
