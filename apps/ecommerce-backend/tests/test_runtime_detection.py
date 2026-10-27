"""Test suite for Phase 5: Agent 7 (Runtime Security Agent), detection rules, and incident persistence."""

import pytest
from httpx import AsyncClient

from agents.runtime_security.runtime_agent import RuntimeSecurityAgent
from telemetry.schemas.events import SecurityIndicators, SecurityTelemetryEvent


def test_sqli_runtime_detection():
    agent = RuntimeSecurityAgent()
    event = SecurityTelemetryEvent(
        session_id="session_sqli_test",
        method="GET",
        path="/api/v1/products",
        query_params={"search": "laptop' OR '1'='1--"},
        status_code=500,
        duration_ms=8.2,
        indicators=SecurityIndicators(has_sql_chars=True, is_server_error=True),
    )

    incidents = agent.analyze_event(event)
    assert len(incidents) >= 1
    inc = incidents[0]
    assert inc.attack_type == "SQL_INJECTION"
    assert inc.cwe_id == "CWE-89"
    assert inc.severity == "HIGH"
    assert inc.confidence >= 0.95
    assert inc.session_id == "session_sqli_test"


def test_xss_runtime_detection():
    agent = RuntimeSecurityAgent()
    event = SecurityTelemetryEvent(
        session_id="session_xss_test",
        method="GET",
        path="/api/v1/products",
        query_params={"search": "<script>alert('xss')</script>"},
        status_code=200,
        duration_ms=3.1,
        indicators=SecurityIndicators(has_script_tags=True),
    )

    incidents = agent.analyze_event(event)
    assert len(incidents) >= 1
    inc = incidents[0]
    assert inc.attack_type == "XSS"
    assert inc.cwe_id == "CWE-79"
    assert inc.severity == "MEDIUM"


def test_brute_force_login_detection():
    agent = RuntimeSecurityAgent(brute_force_threshold=4, window_seconds=60.0)
    session_id = "brute_force_attacker_session"

    # Emit 3 failed logins (below threshold)
    for _ in range(3):
        event = SecurityTelemetryEvent(
            session_id=session_id,
            method="POST",
            path="/api/v1/auth/login",
            status_code=401,
            duration_ms=4.0,
            indicators=SecurityIndicators(is_auth_failure=True),
        )
        assert len(agent.analyze_event(event)) == 0

    # 4th failed login hits threshold
    event = SecurityTelemetryEvent(
        session_id=session_id,
        method="POST",
        path="/api/v1/auth/login",
        status_code=401,
        duration_ms=4.0,
        indicators=SecurityIndicators(is_auth_failure=True),
    )
    incidents = agent.analyze_event(event)
    assert len(incidents) >= 1
    assert incidents[0].attack_type == "BRUTE_FORCE_AUTH"
    assert incidents[0].cwe_id == "CWE-307"
    assert incidents[0].confidence >= 0.95


def test_bola_unauthorized_order_access_detection():
    agent = RuntimeSecurityAgent()
    event = SecurityTelemetryEvent(
        session_id="session_bola_attacker",
        user_id="user_bob",
        method="GET",
        path="/api/v1/orders/1001",
        status_code=403,
        duration_ms=5.0,
        indicators=SecurityIndicators(is_auth_failure=True),
    )

    incidents = agent.analyze_event(event)
    assert len(incidents) >= 1
    assert incidents[0].attack_type == "BOLA_IDOR"
    assert incidents[0].cwe_id == "CWE-284"
    assert incidents[0].severity == "HIGH"


@pytest.mark.asyncio
async def test_detection_worker_stream_processing_and_api(async_client: AsyncClient):
    # 1. Send live attack request that middleware emits into Redis Stream
    sqli_url = "/api/v1/products?search=test' OR '1'='1--"
    res = await async_client.get(sqli_url)
    assert res.status_code in (200, 500)
    session_id = res.headers.get("X-Session-ID")
    assert session_id is not None

    # 2. Trigger detection worker batch processing
    process_res = await async_client.post("/security/v1/detection/process-batch?count=50")
    assert process_res.status_code == 200
    detected_incidents = process_res.json()
    assert len(detected_incidents) >= 1

    # Verify SQL injection was detected from the streamed request
    sqli_incidents = [i for i in detected_incidents if i["attack_type"] == "SQL_INJECTION"]
    assert len(sqli_incidents) >= 1
    assert sqli_incidents[0]["cwe_id"] == "CWE-89"

    # 3. Query incidents endpoint with filters
    list_res = await async_client.get("/security/v1/incidents?attack_type=SQL_INJECTION")
    assert list_res.status_code == 200
    stored_incidents = list_res.json()
    assert len(stored_incidents) >= 1
    assert stored_incidents[0]["attack_type"] == "SQL_INJECTION"
    assert stored_incidents[0]["status"] == "OPEN"
