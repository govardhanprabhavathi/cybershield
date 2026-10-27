import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_trigger_static_scan_api(async_client: AsyncClient):
    response = await async_client.post("/security/v1/scan/static?persist=true")
    assert response.status_code == 200
    report = response.json()

    assert "scan_id" in report
    assert report["total_findings"] >= 3
    assert "findings_by_severity" in report
    assert "findings_by_category" in report
    assert len(report["findings"]) >= 3

    # Verify application map is nested in report
    assert "application_map" in report
    assert report["application_map"]["total_endpoints"] >= 10


@pytest.mark.asyncio
async def test_list_stored_findings_with_filtering(async_client: AsyncClient):
    # Ensure scan has run and persisted findings
    await async_client.post("/security/v1/scan/static?persist=true")

    # List all findings
    all_res = await async_client.get("/security/v1/findings")
    assert all_res.status_code == 200
    findings = all_res.json()
    assert len(findings) >= 3

    # Filter by category
    sqli_res = await async_client.get("/security/v1/findings?category=SQL_INJECTION")
    assert sqli_res.status_code == 200
    sqli_list = sqli_res.json()
    assert len(sqli_list) >= 1
    for f in sqli_list:
        assert f["category"] == "SQL_INJECTION"


@pytest.mark.asyncio
async def test_get_application_map_api(async_client: AsyncClient):
    response = await async_client.get("/security/v1/map")
    assert response.status_code == 200
    app_map = response.json()

    assert app_map["app_name"] == "CyberShield E-Commerce Defense Platform"
    assert app_map["total_endpoints"] >= 10
    assert len(app_map["models"]) >= 5
