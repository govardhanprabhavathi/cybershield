"""Test suite for Phase 6: Session Security Agent, explainable risk scoring, and graduated containment."""

import pytest
from app.core.redis import get_redis
from httpx import AsyncClient

from agents.session_security.session_agent import SessionSecurityAgent
from security.schemas.incident import RuntimeIncident


@pytest.mark.asyncio
async def test_clean_session_baseline():
    agent = SessionSecurityAgent()
    profile = await agent.get_profile("clean_test_session_1")

    assert profile.session_id == "clean_test_session_1"
    assert profile.risk_score == 0
    assert profile.confidence == 0.0
    assert profile.state == "ALLOW"
    assert profile.incident_count == 0
    assert len(profile.attack_types_seen) == 0
    assert "Clean legitimate session baseline" in profile.contributing_factors[0]


@pytest.mark.asyncio
async def test_single_attack_risk_escalation():
    agent = SessionSecurityAgent()
    session_id = "single_attack_session_sqli"

    incident = RuntimeIncident(
        session_id=session_id,
        user_id="user_123",
        client_ip="192.168.1.10",
        attack_type="SQL_INJECTION",
        severity="HIGH",
        confidence=0.95,
        cwe_id="CWE-89",
        endpoint="/api/v1/products",
        method="GET",
        trigger_event_id="evt_101",
    )

    profile = await agent.record_incident(incident)

    assert profile.session_id == session_id
    assert profile.risk_score == 40  # ATTACK_WEIGHTS["SQL_INJECTION"]
    assert profile.confidence >= 0.90
    assert profile.state == "MONITOR"
    assert profile.incident_count == 1
    assert "SQL_INJECTION" in profile.attack_types_seen
    assert any("SQL_INJECTION on /api/v1/products" in factor for factor in profile.contributing_factors)


@pytest.mark.asyncio
async def test_compounded_multi_vector_escalation_to_containment():
    agent = SessionSecurityAgent()
    session_id = "multi_vector_attacker_session"

    inc1 = RuntimeIncident(
        session_id=session_id,
        user_id="user_attacker",
        client_ip="192.168.1.50",
        attack_type="SQL_INJECTION",
        severity="HIGH",
        confidence=0.95,
        cwe_id="CWE-89",
        endpoint="/api/v1/products",
        method="GET",
        trigger_event_id="evt_sqli",
    )
    inc2 = RuntimeIncident(
        session_id=session_id,
        user_id="user_attacker",
        client_ip="192.168.1.50",
        attack_type="BOLA_IDOR",
        severity="HIGH",
        confidence=0.95,
        cwe_id="CWE-284",
        endpoint="/api/v1/orders/order-999",
        method="GET",
        trigger_event_id="evt_bola",
    )

    await agent.record_incident(inc1)
    profile = await agent.record_incident(inc2)

    # Base = 40 (SQLi) + 35 (BOLA) = 75. 1.2x multi-vector multiplier -> 90
    assert profile.risk_score == 90
    assert profile.confidence >= 0.85
    assert profile.state == "CONTAIN"
    assert profile.incident_count == 2
    assert set(profile.attack_types_seen) == {"SQL_INJECTION", "BOLA_IDOR"}
    assert any("1.2x" in f for f in profile.contributing_factors)

    # Verify Redis fast-state reflects containment status
    redis = await get_redis()
    status = await redis.hget(f"session:risk:{session_id}", "status")
    assert status == "CONTAINED"


@pytest.mark.asyncio
async def test_containment_blocks_authenticated_access(async_client: AsyncClient):
    # 1. Login legitimate user
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "attacker@cybershield.io", "password": "AttackerPass123!"},
    )
    assert login_res.status_code == 200
    data = login_res.json()
    token = data["access_token"]
    session_id = data["session_id"]

    headers = {"Authorization": f"Bearer {token}"}

    # 2. Verify user can access profile initially
    me_res = await async_client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200

    # 3. Simulate detection escalating session to CONTAIN
    agent = SessionSecurityAgent()
    await agent.record_incident(
        RuntimeIncident(
            session_id=session_id,
            attack_type="SQL_INJECTION",
            severity="HIGH",
            confidence=0.95,
            cwe_id="CWE-89",
            endpoint="/api/v1/products",
            method="GET",
            trigger_event_id="evt_1",
        )
    )
    await agent.record_incident(
        RuntimeIncident(
            session_id=session_id,
            attack_type="BOLA_IDOR",
            severity="HIGH",
            confidence=0.95,
            cwe_id="CWE-284",
            endpoint="/api/v1/orders/999",
            method="GET",
            trigger_event_id="evt_2",
        )
    )

    # 4. Immediate fast-path containment: next request must be rejected with 403 Forbidden
    blocked_res = await async_client.get("/api/v1/auth/me", headers=headers)
    assert blocked_res.status_code == 403
    assert "contained by CyberShield runtime security policy" in blocked_res.json()["detail"]


@pytest.mark.asyncio
async def test_risk_time_decay():
    agent = SessionSecurityAgent()
    session_id = "decay_test_session"

    # Seed an incident with weight 40 (SQLi)
    await agent.record_incident(
        RuntimeIncident(
            session_id=session_id,
            attack_type="SQL_INJECTION",
            severity="HIGH",
            confidence=0.90,
            cwe_id="CWE-89",
            endpoint="/api/v1/products",
            method="GET",
            trigger_event_id="evt_decay_1",
        )
    )
    p_before = await agent.get_profile(session_id)
    assert p_before.risk_score == 40
    assert p_before.state == "MONITOR"

    # Decay with 10 benign minutes (2 intervals * 5 = -10 points)
    p_after = await agent.decay_session(session_id, elapsed_minutes=10.0)
    assert p_after.risk_score == 30
    assert p_after.state == "MONITOR"

    # Decay with another 15 minutes (3 intervals * 5 = -15 points -> 15 points)
    p_further = await agent.decay_session(session_id, elapsed_minutes=15.0)
    assert p_further.risk_score == 15
    assert p_further.state == "ALLOW"


@pytest.mark.asyncio
async def test_session_reset(async_client: AsyncClient):
    # Login attacker
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "attacker@cybershield.io", "password": "AttackerPass123!"},
    )
    data = login_res.json()
    token = data["access_token"]
    session_id = data["session_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Escalate to CONTAIN
    agent = SessionSecurityAgent()
    await agent.record_incident(
        RuntimeIncident(
            session_id=session_id,
            attack_type="SQL_INJECTION",
            severity="HIGH",
            confidence=0.95,
            cwe_id="CWE-89",
            endpoint="/api/v1/products",
            method="GET",
            trigger_event_id="evt_sqli_rst",
        )
    )
    await agent.record_incident(
        RuntimeIncident(
            session_id=session_id,
            attack_type="BOLA_IDOR",
            severity="HIGH",
            confidence=0.95,
            cwe_id="CWE-284",
            endpoint="/api/v1/orders/1",
            method="GET",
            trigger_event_id="evt_bola_rst",
        )
    )

    # Confirm blocked
    blocked = await async_client.get("/api/v1/auth/me", headers=headers)
    assert blocked.status_code == 403

    # Reset session via REST API
    reset_res = await async_client.post(f"/security/v1/sessions/{session_id}/reset")
    assert reset_res.status_code == 200
    reset_profile = reset_res.json()
    assert reset_profile["risk_score"] == 0
    assert reset_profile["state"] == "ALLOW"

    # If user logs in again, they have normal access
    re_login = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "attacker@cybershield.io", "password": "AttackerPass123!"},
    )
    new_token = re_login.json()["access_token"]
    new_res = await async_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert new_res.status_code == 200


@pytest.mark.asyncio
async def test_high_risk_sessions_ranking():
    agent = SessionSecurityAgent()

    # Session Low (Resource: 20)
    await agent.record_incident(
        RuntimeIncident(
            session_id="session_rank_low",
            attack_type="RESOURCE_CONSUMPTION",
            severity="LOW",
            confidence=0.85,
            cwe_id="CWE-770",
            endpoint="/api/v1/products",
            method="GET",
            trigger_event_id="evt_rank_1",
        )
    )

    # Session Mid (SQLi: 40)
    await agent.record_incident(
        RuntimeIncident(
            session_id="session_rank_mid",
            attack_type="SQL_INJECTION",
            severity="HIGH",
            confidence=0.90,
            cwe_id="CWE-89",
            endpoint="/api/v1/products",
            method="GET",
            trigger_event_id="evt_rank_2",
        )
    )

    # Session High (SQLi + BOLA: 90)
    await agent.record_incident(
        RuntimeIncident(
            session_id="session_rank_high",
            attack_type="SQL_INJECTION",
            severity="HIGH",
            confidence=0.95,
            cwe_id="CWE-89",
            endpoint="/api/v1/products",
            method="GET",
            trigger_event_id="evt_rank_3",
        )
    )
    await agent.record_incident(
        RuntimeIncident(
            session_id="session_rank_high",
            attack_type="BOLA_IDOR",
            severity="HIGH",
            confidence=0.95,
            cwe_id="CWE-284",
            endpoint="/api/v1/orders/2",
            method="GET",
            trigger_event_id="evt_rank_4",
        )
    )

    high_risk = await agent.get_high_risk_sessions(min_risk=30)
    sids = [p.session_id for p in high_risk]

    assert "session_rank_high" in sids
    assert "session_rank_mid" in sids
    assert "session_rank_low" not in sids
    # Ranked high to mid
    assert sids.index("session_rank_high") < sids.index("session_rank_mid")


@pytest.mark.asyncio
async def test_session_risk_rest_endpoints(async_client: AsyncClient):
    # 1. Matrix endpoint
    matrix_res = await async_client.get("/security/v1/sessions/matrix")
    assert matrix_res.status_code == 200
    tiers = matrix_res.json()
    tier_names = [t["tier"] for t in tiers]
    assert tier_names == ["ALLOW", "MONITOR", "THROTTLE", "CHALLENGE", "CONTAIN"]

    # 2. Risk profile query endpoint
    risk_res = await async_client.get("/security/v1/sessions/test_rest_session_query/risk")
    assert risk_res.status_code == 200
    data = risk_res.json()
    assert data["session_id"] == "test_rest_session_query"
    assert data["state"] == "ALLOW"

    # 3. High risk query endpoint
    high_res = await async_client.get("/security/v1/sessions/high-risk?min_risk=0")
    assert high_res.status_code == 200
    assert isinstance(high_res.json(), list)

    # 4. Decay endpoint
    decay_res = await async_client.post("/security/v1/sessions/test_rest_session_query/decay?elapsed_minutes=10.0")
    assert decay_res.status_code == 200
    assert decay_res.json()["risk_score"] == 0


@pytest.mark.asyncio
async def test_detection_worker_triggers_session_containment(async_client: AsyncClient):
    # 1. Login user
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "alice@cybershield.io", "password": "AlicePass123!"},
    )
    token = login_res.json()["access_token"]
    session_id = login_res.json()["session_id"]
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Session-ID": session_id,
    }

    # 2. Send multi-vector attacks reusing the authenticated session ID:
    # A) SQL Injection probe
    await async_client.get("/api/v1/products?search=item' OR 1=1--", headers=headers)
    # B) BOLA order enumeration probes (3 distinct orders)
    await async_client.get("/api/v1/orders/enum-1", headers=headers)
    await async_client.get("/api/v1/orders/enum-2", headers=headers)
    await async_client.get("/api/v1/orders/enum-3", headers=headers)

    # 3. Trigger worker batch processing until stream is drained
    for _ in range(5):
        batch_res = await async_client.post("/security/v1/detection/process-batch?count=100")
        assert batch_res.status_code == 200
        if not batch_res.json():
            break

    # 4. Query session risk
    session_risk_res = await async_client.get(f"/security/v1/sessions/{session_id}/risk")
    assert session_risk_res.status_code == 200
    risk_data = session_risk_res.json()
    assert risk_data["state"] == "CONTAIN"
    assert risk_data["risk_score"] >= 90

    # 5. Fast-path check: Alice is now contained and cannot make further authenticated requests
    contained_req = await async_client.get("/api/v1/auth/me", headers=headers)
    assert contained_req.status_code == 403
