"""Integration tests for the AI Security Orchestrator REST API endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_orchestrator_rest_api_lifecycle(async_client: AsyncClient):
    """Test full workflow trigger, querying, approval, and RCA endpoints."""
    # 1. Trigger an autonomous incident workflow
    trigger_payload = {
        "cwe_id": "CWE-89",
        "normalized_route": "/api/v1/products/search",
        "severity": "MEDIUM",
        "governance_mode": "FULLY_AUTONOMOUS",
        "session_id": "sess_test_api_client",
    }
    trigger_res = await async_client.post(
        "/security/v1/orchestrator/workflows/trigger", json=trigger_payload
    )
    assert trigger_res.status_code == 201
    trigger_data = trigger_res.json()
    assert trigger_data["status"] == "success"
    workflow = trigger_data["workflow"]
    workflow_id = workflow["id"]
    assert workflow_id.startswith("WF-")
    assert workflow["state"] == "RESOLVED"

    # 2. List workflows
    list_res = await async_client.get("/security/v1/orchestrator/workflows")
    assert list_res.status_code == 200
    wf_list = list_res.json()
    assert len(wf_list) >= 1
    assert any(w["id"] == workflow_id for w in wf_list)

    # Filter workflows by CWE
    filter_res = await async_client.get("/security/v1/orchestrator/workflows?cwe_id=CWE-89")
    assert filter_res.status_code == 200
    assert len(filter_res.json()) >= 1

    # 3. Retrieve single workflow detail
    detail_res = await async_client.get(f"/security/v1/orchestrator/workflows/{workflow_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == workflow_id
    assert detail["cwe_id"] == "CWE-89"
    assert len(detail["steps"]) >= 4
    assert len(detail["playbook_actions"]) >= 1

    # 4. Query RCA report endpoint
    rca_res = await async_client.get(f"/security/v1/orchestrator/workflows/{workflow_id}/rca")
    assert rca_res.status_code == 200
    rca_data = rca_res.json()
    assert rca_data.get("cwe_id") == "CWE-89"
    assert "blast_radius" in rca_data

    # 5. Trigger a Human-in-the-Loop workflow with HIGH severity
    hitl_payload = {
        "cwe_id": "CWE-284",
        "normalized_route": "/api/v1/orders/{order_id}",
        "severity": "HIGH",
        "governance_mode": "HUMAN_IN_THE_LOOP",
        "session_id": "sess_test_hitl",
    }
    hitl_res = await async_client.post(
        "/security/v1/orchestrator/workflows/trigger", json=hitl_payload
    )
    assert hitl_res.status_code == 201
    hitl_wf_id = hitl_res.json()["workflow"]["id"]
    assert hitl_res.json()["workflow"]["state"] == "AWAITING_APPROVAL"

    # 6. Approve the pending HITL workflow
    approve_res = await async_client.post(
        f"/security/v1/orchestrator/workflows/{hitl_wf_id}/approve",
        json={"approved": True, "reviewer": "ciso_reviewer", "comments": "Verified and approved"},
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["state"] == "RESOLVED"

    # 7. Nonexistent workflow returns 404
    missing_res = await async_client.get("/security/v1/orchestrator/workflows/WF-NONEXISTENT")
    assert missing_res.status_code == 404
