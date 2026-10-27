import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_new_user(async_client: AsyncClient):
    response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "charlie@cybershield.io",
            "password": "CharliePassword123!",
            "full_name": "Charlie Customer",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "charlie@cybershield.io"
    assert data["role"] == "customer"
    assert "id" in data


@pytest.mark.asyncio
async def test_register_duplicate_email(async_client: AsyncClient):
    response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@cybershield.io",
            "password": "AnyPassword123!",
            "full_name": "Alice Duplicate",
        },
    )
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"]


@pytest.mark.asyncio
async def test_login_success(async_client: AsyncClient):
    response = await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": "alice@cybershield.io",
            "password": "AlicePass123!",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "session_id" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_invalid_credentials(async_client: AsyncClient):
    response = await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": "alice@cybershield.io",
            "password": "WrongPassword!",
        },
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_profile(async_client: AsyncClient):
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": "alice@cybershield.io",
            "password": "AlicePass123!",
        },
    )
    token = login_res.json()["access_token"]

    profile_res = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert profile_res.status_code == 200
    data = profile_res.json()
    assert data["email"] == "alice@cybershield.io"
    assert data["full_name"] == "Alice Shopper"


@pytest.mark.asyncio
async def test_logout_and_token_revocation(async_client: AsyncClient):
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": "bob@cybershield.io",
            "password": "BobPass123!",
        },
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify token works
    valid_res = await async_client.get("/api/v1/auth/me", headers=headers)
    assert valid_res.status_code == 200

    # Logout
    logout_res = await async_client.post("/api/v1/auth/logout", headers=headers)
    assert logout_res.status_code == 200
    assert logout_res.json()["status"] == "success"

    # Subsequent request using the revoked token must fail with 401
    revoked_res = await async_client.get("/api/v1/auth/me", headers=headers)
    assert revoked_res.status_code == 401
    assert "revoked" in revoked_res.json()["detail"].lower()
