"""Test suite for Phase 3: Agent 3 (API Security Agent DAST) and dynamic scan orchestrator."""

import pytest
from app.core.config import get_settings
from app.main import app
from httpx import AsyncClient

from agents.api_security.api_security_agent import APISecurityAgent


@pytest.mark.asyncio
async def test_dynamic_sqli_probe_toggle_sensitivity(async_client: AsyncClient):
    settings = get_settings()
    agent = APISecurityAgent(client=async_client, app=app)

    # 1. Test when SQLi is enabled
    settings.ENABLE_VULNERABILITY_SQLI = True
    vuln_result = await agent.probe_sqli("/api/v1/products")
    assert vuln_result.vulnerable is True
    assert vuln_result.finding is not None
    assert vuln_result.finding.category == "SQL_INJECTION"
    assert vuln_result.finding.cwe_id == "CWE-89"
    assert vuln_result.finding.confidence >= 0.98

    # 2. Test when SQLi is disabled
    settings.ENABLE_VULNERABILITY_SQLI = False
    safe_result = await agent.probe_sqli("/api/v1/products")
    assert safe_result.vulnerable is False
    assert safe_result.finding is None

    # Reset toggle to default
    settings.ENABLE_VULNERABILITY_SQLI = True


@pytest.mark.asyncio
async def test_dynamic_bola_probe_toggle_sensitivity(async_client: AsyncClient):
    settings = get_settings()
    agent = APISecurityAgent(client=async_client, app=app)

    # Obtain tokens for Alice (victim) and Bob (attacker)
    alice_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "alice@cybershield.io", "password": "AlicePass123!"},
    )
    bob_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "bob@cybershield.io", "password": "BobPass123!"},
    )
    alice_token = alice_res.json()["access_token"]
    bob_token = bob_res.json()["access_token"]

    # Discover Alice's order
    orders_res = await async_client.get(
        "/api/v1/orders",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    alice_orders = orders_res.json()
    assert len(alice_orders) >= 1
    alice_order_id = alice_orders[0]["id"]

    # 1. Test when BOLA is enabled
    settings.ENABLE_VULNERABILITY_BOLA = True
    vuln_result = await agent.probe_bola(
        victim_token=alice_token,
        attacker_token=bob_token,
        victim_order_id=alice_order_id,
    )
    assert vuln_result.vulnerable is True
    assert vuln_result.finding is not None
    assert vuln_result.finding.category == "BOLA_IDOR"
    assert vuln_result.finding.confidence >= 0.99
    assert vuln_result.finding.status == "CONFIRMED"

    # 2. Test when BOLA is disabled
    settings.ENABLE_VULNERABILITY_BOLA = False
    safe_result = await agent.probe_bola(
        victim_token=alice_token,
        attacker_token=bob_token,
        victim_order_id=alice_order_id,
    )
    assert safe_result.vulnerable is False
    assert safe_result.finding is None

    # Reset toggle to default
    settings.ENABLE_VULNERABILITY_BOLA = True


@pytest.mark.asyncio
async def test_dynamic_business_flow_probe(async_client: AsyncClient):
    settings = get_settings()
    agent = APISecurityAgent(client=async_client, app=app)

    alice_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "alice@cybershield.io", "password": "AlicePass123!"},
    )
    alice_token = alice_res.json()["access_token"]

    products_res = await async_client.get("/api/v1/products?limit=1")
    product_id = products_res.json()[0]["id"]

    # 1. When Business Flow Flaw is enabled
    settings.ENABLE_VULNERABILITY_BUSINESS_FLOW = True
    vuln_result = await agent.probe_business_flow(user_token=alice_token, product_id=product_id)
    assert vuln_result.vulnerable is True
    assert vuln_result.finding is not None
    assert vuln_result.finding.category == "BUSINESS_FLOW_ABUSE"

    # 2. When Business Flow Flaw is disabled
    settings.ENABLE_VULNERABILITY_BUSINESS_FLOW = False
    safe_result = await agent.probe_business_flow(user_token=alice_token, product_id=product_id)
    assert safe_result.vulnerable is False

    # Reset toggle
    settings.ENABLE_VULNERABILITY_BUSINESS_FLOW = True


def test_openapi_contract_audit_and_zap_exporter(async_client: AsyncClient):
    agent = APISecurityAgent(client=async_client, app=app)

    # Audit OpenAPI Contract
    status, issues = agent.audit_openapi_contract(app)
    assert status in ("PASSED", "WARNINGS_FOUND")
    assert isinstance(issues, list)

    # Generate OWASP ZAP Automation Plan
    zap_plan = agent.generate_zap_automation_plan(target_url="http://localhost:8000")
    assert "cybershield-api" in zap_plan
    assert "activeScan" in zap_plan
    assert "spider" in zap_plan
    assert "openapi" in zap_plan


@pytest.mark.asyncio
async def test_dynamic_scan_api_and_sast_correlation(async_client: AsyncClient):
    # Step 1: Run static scan to populate baseline SAST findings
    static_res = await async_client.post("/security/v1/scan/static?persist=true")
    assert static_res.status_code == 200
    static_report = static_res.json()
    assert static_report["total_findings"] >= 3

    # Step 2: Run dynamic scan to execute DAST probes and correlate with SAST
    dynamic_res = await async_client.post("/security/v1/scan/dynamic?persist=true")
    assert dynamic_res.status_code == 200
    dynamic_report = dynamic_res.json()

    assert dynamic_report["probes_executed"] >= 3
    assert dynamic_report["vulnerabilities_confirmed"] >= 2
    assert dynamic_report["confirmed_sast_count"] >= 2

    # Step 3: Verify confirmed findings endpoint returns upgraded findings
    confirmed_res = await async_client.get("/security/v1/findings/confirmed")
    assert confirmed_res.status_code == 200
    confirmed_list = confirmed_res.json()
    assert len(confirmed_list) >= 2

    confirmed_categories = {f["category"] for f in confirmed_list}
    assert "BOLA_IDOR" in confirmed_categories
    assert "SQL_INJECTION" in confirmed_categories

    for f in confirmed_list:
        assert f["status"] == "CONFIRMED"
        assert f["confidence"] >= 0.95
        assert "dast_confirmation" in f["raw_evidence"]


@pytest.mark.asyncio
async def test_get_zap_config_endpoint(async_client: AsyncClient):
    res = await async_client.get("/security/v1/scan/dynamic/zap-config?target_url=http://127.0.0.1:8000")
    assert res.status_code == 200
    assert "cybershield-api" in res.text
    assert "http://127.0.0.1:8000" in res.text
